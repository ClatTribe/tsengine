package platformapi

import (
	"context"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// trustedProxies is the set of proxy IPs/CIDRs whose forwarded-for header we trust. Parsed once from
// TSENGINE_TRUSTED_PROXY_CIDRS (comma-separated CIDRs or bare IPs — e.g. the prod Caddy edge's network).
// Empty → we trust no proxy and always key the rate limiter off RemoteAddr (correct for a directly-
// exposed deployment). Behind a reverse proxy this MUST be set, or RemoteAddr is the proxy's IP for
// every request and all public traffic shares one rate-limit bucket.
var trustedProxies = parseTrustedProxies(os.Getenv("TSENGINE_TRUSTED_PROXY_CIDRS"))

func parseTrustedProxies(s string) []*net.IPNet {
	var out []*net.IPNet
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") { // allow a bare IP → /32 or /128
			if ip := net.ParseIP(p); ip != nil {
				if ip.To4() != nil {
					p += "/32"
				} else {
					p += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipInCIDRs(ipStr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the request's real client IP for per-IP rate-limiting. When the connection comes
// from a trusted proxy (RemoteAddr ∈ trustedProxies), it reads the forwarded client; otherwise it uses
// RemoteAddr. It NEVER trusts a forwarded header from an untrusted peer — that would let a client forge
// X-Forwarded-For to spoof another user's limiter key or bypass the limit. With a trusted proxy it
// takes the RIGHTMOST X-Forwarded-For entry that is not itself a trusted proxy: each proxy appends the
// peer it actually saw, so any entry to the right of the trusted chain is attacker-uncontrollable.
func clientIP(r *http.Request) string { return clientIPFrom(r, trustedProxies) }

func clientIPFrom(r *http.Request, trusted []*net.IPNet) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if len(trusted) == 0 || !ipInCIDRs(host, trusted) {
		return host // direct connection (or no trusted proxy configured) → RemoteAddr is authoritative
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if net.ParseIP(ip) == nil {
			continue
		}
		if ipInCIDRs(ip, trusted) {
			continue // skip trusted proxy hops
		}
		return ip // rightmost non-trusted entry = the real client
	}
	return host // no usable forwarded entry → fall back to the proxy IP
}

// The public PLG instant assessment (top-of-funnel lead magnet). Anyone, with no account, can
// enter a domain and get a security score from a GROUNDED, READ-ONLY check: email-auth posture
// (DMARC / SPF / DKIM) resolved from public DNS via the same operate engine. It never scans the
// target's servers — only public DNS lookups anyone can do — so it's safe to expose
// unauthenticated. "Sign up to fix" is the conversion. The full multi-surface assessment is
// gated behind connecting a system.

// assessResult is the public-safe response: a score + the questionnaire-readiness checks + teaser
// findings. The Questionnaire summary reframes the checks in the founder's language ("you'd fail N
// of M checks an enterprise security questionnaire asks") — the conversion hook for the SOC2 ICP.
type assessResult struct {
	Domain        string               `json:"domain"`
	Score         int                  `json:"score"` // 0-100
	Grade         string               `json:"grade"` // A | B | C | D | F
	Questionnaire questionnaireSummary `json:"questionnaire"`
	Checks        []assessCheck        `json:"checks"`
	Findings      []assessFinding      `json:"findings"`
}

// questionnaireSummary is the founder-facing reframing of the check set.
type questionnaireSummary struct {
	Failed   int    `json:"failed"`
	Total    int    `json:"total"`
	Headline string `json:"headline"`
}

// assess combines the email-auth posture (public DNS) with the web posture (public HTTPS) into the
// full questionnaire-readiness report. Pure given its inputs (the I/O happens in the handler), so the
// scoring is deterministic + testable.
func assess(dc operate.DomainConfig, wp webPosture) assessResult {
	res := assessEmailAuth(dc)
	wc, wf, penalty := assessWeb(wp)
	res.Checks = append(res.Checks, wc...)
	res.Findings = append(res.Findings, wf...)
	res.Score -= penalty
	if res.Score < 0 {
		res.Score = 0
	}
	res.Grade = grade(res.Score)
	res.Questionnaire = summarize(res.Checks)
	return res
}

type assessCheck struct {
	Name   string    `json:"name"`
	OK     bool      `json:"ok"`
	Detail string    `json:"detail"`
	Fix    *checkFix `json:"fix,omitempty"` // copy-paste remediation; present only when !OK
}

type assessFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// reservedSuffixes are non-public namespaces (RFC 6761/6762 special-use + cloud-metadata internal
// zones) that an external assessment must never resolve or connect to. Refusing them here is
// belt-and-suspenders ahead of the connect-time SSRF guard (safeHTTPClient, which already rejects a
// resolved private/link-local IP) — and turns a misleading "degraded grade" into a clear refusal for
// inputs like metadata.google.internal (resolves to the 169.254.169.254 metadata IP on GCP).
var reservedSuffixes = []string{
	".local", ".localhost", ".internal", ".intranet", ".lan", ".corp", ".private", ".home.arpa",
}

// normalizeDomain lowercases + strips scheme/path/port, and rejects IPs / localhost / bare
// hosts / reserved-internal namespaces. Returns "" when the input isn't a public domain we should look up.
func normalizeDomain(in string) string {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	if d == "" || len(d) > 253 || d == "localhost" || net.ParseIP(d) != nil || !domainRe.MatchString(d) {
		return ""
	}
	for _, s := range reservedSuffixes {
		if strings.HasSuffix(d, s) {
			return ""
		}
	}
	return d
}

// assessEmailAuth turns a resolved DomainConfig into the public score/grade/checks/findings.
// Pure (no I/O) so it is deterministic + testable; the DNS resolution happens in the handler.
func assessEmailAuth(dc operate.DomainConfig) assessResult {
	enforced := dc.DMARC == "reject" || dc.DMARC == "quarantine"
	res := assessResult{Domain: dc.Name, Score: 100}
	res.Checks = []assessCheck{
		{Name: "DMARC enforcement", OK: enforced, Detail: dmarcDetail(dc.DMARC), Fix: ifFail(!enforced, dmarcFix(dc.Name))},
		{Name: "SPF", OK: dc.SPF, Detail: ternary(dc.SPF, "Sender Policy Framework record present.", "No SPF record — senders can't be validated."), Fix: ifFail(!dc.SPF, spfFix(dc.Name))},
		{Name: "DKIM", OK: dc.DKIM, Detail: ternary(dc.DKIM, "DKIM signing key published.", "No DKIM key at the common selectors we check. DKIM uses domain-specific selectors DNS can't enumerate, so your provider may publish one we couldn't see — confirm in your mail settings."), Fix: ifFail(!dc.DKIM, dkimFix())},
	}
	// Penalise from the grounded operate findings so the score reflects the same engine logic.
	for _, f := range operate.Assess(operate.Workspace{Org: dc.Name, Domains: []operate.DomainConfig{dc}}, operate.Options{}) {
		res.Findings = append(res.Findings, assessFinding{Title: f.Title, Severity: string(f.Severity)})
		res.Score -= severityPenalty(f.Severity)
	}
	if res.Score < 0 {
		res.Score = 0
	}
	res.Grade = grade(res.Score)
	return res
}

func dmarcDetail(p string) string {
	switch p {
	case "reject":
		return "DMARC p=reject — spoofed mail is rejected. Strongest setting."
	case "quarantine":
		return "DMARC p=quarantine — spoofed mail is quarantined."
	case "none":
		return "DMARC p=none — monitoring only; attackers can still spoof you."
	default:
		return "No DMARC record — anyone can spoof your domain for phishing/BEC."
	}
}

func severityPenalty(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 45
	case types.SeverityHigh:
		return 30
	case types.SeverityMedium:
		return 15
	case types.SeverityLow:
		return 5
	default:
		return 0
	}
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func ternary(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// assessLimiter is a tiny per-IP rate limiter for the public endpoint (read-only DNS, low abuse
// risk, but bound it anyway): max N requests per rolling minute.
type assessLimiter struct {
	mu  sync.Mutex
	hit map[string][]time.Time
	max int
}

var publicAssessLimiter = &assessLimiter{hit: map[string][]time.Time{}, max: 20}

func (l *assessLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	kept := l.hit[ip][:0]
	for _, t := range l.hit[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hit[ip] = kept
		return false
	}
	l.hit[ip] = append(kept, now)
	return true
}

// handlePublicAssess (PUBLIC — no bearer) runs the instant email-auth assessment for a domain.
func (d Deps) handlePublicAssess(w http.ResponseWriter, r *http.Request) {
	domain := normalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, errBody("enter a valid domain, e.g. acme.com"))
		return
	}
	if !publicAssessLimiter.allow(clientIP(r), time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, errBody("too many requests — try again in a minute"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()
	// Email-auth (DNS) and web posture (HTTPS) are independent — run them concurrently to keep the
	// public endpoint snappy. Both are read-only and public-safe.
	var dc operate.DomainConfig
	var wp webPosture
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); dc = operate.NewEmailAuth().FetchDomain(ctx, domain) }()
	go func() { defer wg.Done(); wp = probeWeb(ctx, domain) }()
	wg.Wait()
	writeJSON(w, http.StatusOK, assess(dc, wp))
}
