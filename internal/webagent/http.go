// Package webagent is the autonomous web/API offensive agent (roadmap §1,
// docs/design/web-agent.md): the LLM brain drives a small tool catalog to send
// crafted requests at a target, reads DETERMINISTIC indicators of the response,
// and records findings that are STRUCTURALLY GROUNDED — a finding is rejected
// unless a real request/response in the attack history carries the indicator for
// the claimed vulnerability class. Findings ride on indicators, not on the model's
// reading of attacker-controlled text, which is also the core defense against
// indirect prompt injection.
package webagent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Requester is the safety layer between the agent and the network. It enforces a
// host ALLOWLIST (no off-scope requests, even if the LLM invents one), a request
// CAP (no runaway / accidental DoS), and a min-interval THROTTLE — all structural,
// none LLM-trusted (the cloudsafety principle).
type Requester struct {
	client      *http.Client
	allow       map[string]bool
	max         int
	minInterval time.Duration

	sent int
	last time.Time
}

// NewRequester builds a Requester scoped to allowHosts (lowercased host[:port]).
func NewRequester(allowHosts []string, maxRequests int, minInterval time.Duration) *Requester {
	allow := map[string]bool{}
	for _, h := range allowHosts {
		allow[strings.ToLower(h)] = true
	}
	// A cookie jar persists Set-Cookie across requests, so once the agent logs in it STAYS
	// authenticated on every later request. Without it each post-login request went out with no
	// session and silently hit the logged-out view — the auth-chain dead end that made every
	// authenticated surface unreachable. The jar is per-Requester (fresh per engagement, no
	// cross-target leakage) and the agent is host-allowlisted anyway. cookiejar.New(nil) never errors.
	jar, _ := cookiejar.New(nil)
	return &Requester{
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noFollow, Jar: jar},
		allow:  allow, max: maxRequests, minInterval: minInterval,
	}
}

func noFollow(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Resp is the part of a response the agent reasons over.
type Resp struct {
	Status    int
	Body      string
	Location  string
	SetCookie []string // raw Set-Cookie header values from THIS response — the session token(s) the agent may need to inspect/forge (server-set metadata, capped)
	Elapsed   time.Duration
}

// Sent reports how many requests have been made (for budget display).
func (r *Requester) Sent() int { return r.sent }

// Send fires one request, enforcing the allowlist + cap + throttle.
func (r *Requester) Send(ctx context.Context, method, rawURL, body string, headers map[string]string) (*Resp, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if !r.allow[strings.ToLower(u.Host)] {
		return nil, fmt.Errorf("OUT OF SCOPE: %q is not in the authorized target allowlist — request blocked", u.Host)
	}
	if r.sent >= r.max {
		return nil, fmt.Errorf("request budget exhausted (%d) — stop and report what you have", r.max)
	}
	if r.minInterval > 0 {
		if wait := r.minInterval - time.Since(r.last); wait > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), rawURL, rdr) //nolint:gosec // host is allowlist-checked above
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r.sent++
	r.last = time.Now()
	start := time.Now()
	httpResp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
	return &Resp{
		Status: httpResp.StatusCode, Body: string(b),
		Location:  httpResp.Header.Get("Location"),
		SetCookie: capCookies(httpResp.Header["Set-Cookie"]),
		Elapsed:   time.Since(start),
	}, nil
}

// cookieMaxLen bounds a single Set-Cookie value recorded/surfaced — generous enough to hold a full
// session JWT (which the agent may need to inspect for a token-forgery / IDOR chain) yet bounded so a
// pathological cookie can't bloat the transcript / evidence.
const cookieMaxLen = 4096

// capCookies caps each raw Set-Cookie value (nil in → nil out, so a cookieless response records nothing).
func capCookies(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		if len(c) > cookieMaxLen {
			c = c[:cookieMaxLen] + "…"
		}
		out = append(out, c)
	}
	return out
}

// cookieName extracts the NAME of a Set-Cookie header value (the part before '='), for a stable
// deterministic indicator. "session=eyJ…; Path=/" → "session". Names are case-sensitive per RFC 6265,
// so it is preserved as-is.
func cookieName(raw string) string {
	if i := strings.IndexByte(raw, '='); i > 0 {
		return strings.TrimSpace(raw[:i])
	}
	return strings.TrimSpace(raw)
}

// --- deterministic indicators (the grounding substrate) ---

var sqlErrRe = regexp.MustCompile(`(?i)(SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|SQLITE_ERROR|PG::\w+Error|psql:|Unclosed quotation mark|quoted string not properly terminated|SQLSTATE\[|syntax error at or near|Microsoft OLE DB|ODBC SQL Server)`)

// fileDiscRe matches the unmistakable shape of a sensitive file leaked into the
// response — /etc/passwd line, Windows win.ini section. The signal of a successful
// path traversal / LFI.
var fileDiscRe = regexp.MustCompile(`(?i)(root:[^:]*:0:0:|daemon:[x*]:1:1:|\[fonts\]|\[extensions\]|; for 16-bit app support)`)

// cmdOutRe matches the output of a benign probe command (id / uname) reflected in
// the response — the signal of OS command injection.
var cmdOutRe = regexp.MustCompile(`(uid=\d+\([^)]*\)\s+gid=\d+\(|Linux [\w.-]+ \d+\.\d+\.|Darwin Kernel Version)`)

// indicators are deterministic, evidence-grade signals extracted from a response.
// A finding may ONLY be recorded against a turn that carries the matching indicator.
func indicators(payload string, resp *Resp) []string {
	var ind []string
	if sqlErrRe.MatchString(resp.Body) {
		ind = append(ind, "sql_error")
	}
	if payload != "" && looksInjectable(payload) && strings.Contains(resp.Body, payload) {
		ind = append(ind, "reflected_input") // raw, unescaped reflection ⇒ potential XSS
	}
	if fileDiscRe.MatchString(resp.Body) {
		ind = append(ind, "file_disclosure") // path traversal / LFI
	}
	if cmdOutRe.MatchString(resp.Body) {
		ind = append(ind, "cmd_output") // OS command injection
	}
	if resp.Status >= 300 && resp.Status < 400 && resp.Location != "" {
		ind = append(ind, "redirect:"+resp.Location) // informational
		// open redirect is proven only when the response sends the browser to the
		// EXTERNAL host the attacker injected — a same-origin redirect (Location is a
		// bare path, no host) is NOT a finding. This is what tells an exploitable
		// redirect apart from a safe one.
		if payload != "" {
			if loc, err := url.Parse(resp.Location); err == nil && loc.Host != "" && strings.Contains(payload, loc.Host) {
				ind = append(ind, "external_redirect:"+loc.Host)
			}
		}
	}
	if resp.Elapsed > 4*time.Second {
		ind = append(ind, "slow_response") // time-based blind signal
	}
	if resp.Status == 403 || resp.Status == 406 || resp.Status == 429 {
		ind = append(ind, fmt.Sprintf("blocked_%d", resp.Status)) // WAF/filter signal
	}
	for _, c := range resp.SetCookie {
		ind = append(ind, "cookie_set:"+cookieName(c)) // session established/rotated — informational, like redirect:
	}
	return ind
}

func looksInjectable(payload string) bool {
	return strings.ContainsAny(payload, "<>\"'") || strings.Contains(payload, "script")
}

func hasIndicator(turn Turn, want string) bool {
	for _, i := range turn.Indicators {
		if i == want || strings.HasPrefix(i, want) {
			return true
		}
	}
	return false
}
