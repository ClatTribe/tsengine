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
	"strconv"
	"strings"
	"time"
)

// Requester is the safety layer between the agent and the network. It enforces a
// host ALLOWLIST (no off-scope requests, even if the LLM invents one), a request
// CAP (no runaway / accidental DoS), and a min-interval THROTTLE — all structural,
// none LLM-trusted (the cloudsafety principle).
type Requester struct {
	client      *http.Client
	jar         http.CookieJar // persistence store; NOT attached to client.Jar so an explicit Cookie header can override it (token forgery)
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
	// The jar is held on the Requester, NOT on client.Jar: Go's client auto-APPENDS jar cookies after
	// any explicit Cookie header, and a duplicate cookie name means the server keeps one (usually the
	// jar's original) -- so an explicit forged/overridden token (Bearer <other-id>, a re-signed JWT)
	// was silently clobbered by the login cookie, dead-ending EVERY token-forgery IDOR/privesc chain.
	// Sending cookies manually (mergeCookieHeader) lets an explicit Cookie header override the jar
	// per-name while still persisting the login cookie for normal authed requests.
	return &Requester{
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noFollow},
		jar:    jar,
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

// AllowHosts returns the scope host allowlist (lowercased host[:port]) as a slice, so a caller can
// build a FRESH, isolated Requester with the SAME scope — needed by the BOLA differential, which runs
// three sessions (victim / attacker / unauthenticated) whose cookie jars must not cross-contaminate.
func (r *Requester) AllowHosts() []string {
	hs := make([]string, 0, len(r.allow))
	for h := range r.allow {
		hs = append(hs, h)
	}
	return hs
}

// HostInScope reports whether bareHost matches the HOSTNAME of any authorized entry (any port). SSH
// lateral movement (ssh_exec) reaches the target box on a service port (22) distinct from the web
// port, so scope is enforced at host granularity — the agent is authorized against the box, not one
// port. A bare host with no authorized surface is refused, so ssh_exec can never touch a host the
// LLM invents.
func (r *Requester) HostInScope(bareHost string) bool {
	bareHost = strings.ToLower(strings.TrimSpace(bareHost))
	if bareHost == "" {
		return false
	}
	for h := range r.allow {
		hn := h
		if i := strings.LastIndex(hn, ":"); i >= 0 {
			hn = hn[:i]
		}
		if hn == bareHost {
			return true
		}
	}
	return false
}

// AllowedURL reports whether rawURL's host is in the scope allowlist — the SAME guard Send enforces,
// exposed so other host-side tools (e.g. the headless browser) apply identical scope before acting.
func (r *Requester) AllowedURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return r.allow[strings.ToLower(u.Host)]
}

// Send fires one request, enforcing the allowlist + cap + throttle.
func (r *Requester) Send(ctx context.Context, method, rawURL, body string, headers map[string]string) (*Resp, error) {
	// A raw space (or other request-line-breaking whitespace) in the URL can't be sent — it splits the
	// HTTP request line and the server 400s with no useful signal (the XBEN-009 `{% debug %}` dead end).
	// Reject it with an ACTIONABLE hint to percent-encode, rather than silently re-encoding the URL —
	// silent encoding would clobber the deliberate encoding tricks the agent needs (SSTI `{% %}`,
	// double-encoded traversal, …). Only mechanical whitespace is caught; every payload char is left
	// untouched. Returns before the budget counter, so a fixable typo never costs a request.
	if strings.ContainsAny(rawURL, " \t\r\n") {
		return nil, fmt.Errorf("URL contains raw whitespace — percent-encode query values before sending (space→%%20, and a literal %% →%%25); the HTTP request line cannot carry a raw space. Leave deliberate payload characters (../, {%%..%%}) as-is; encode only what the wire needs")
	}
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
	var explicitCookie string
	for k, v := range headers {
		if strings.EqualFold(k, "Cookie") {
			explicitCookie = v // handled below (merge with jar, explicit wins per-name); don't set here
			continue
		}
		req.Header.Set(k, v)
	}
	// Send cookies manually: jar (persisted login) merged with any explicit Cookie header, where the
	// explicit value WINS per name -- so the agent can forge/override a session token for an IDOR/
	// privesc chain. Empty result => no Cookie header (unauthenticated), matching a fresh client.
	if merged := mergeCookieHeader(r.jar.Cookies(u), explicitCookie); merged != "" {
		req.Header.Set("Cookie", merged)
	}
	r.sent++
	r.last = time.Now()
	start := time.Now()
	httpResp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	// Persist this response's Set-Cookie into the jar (the client has no Jar of its own now).
	if rc := httpResp.Cookies(); len(rc) > 0 {
		r.jar.SetCookies(u, rc)
	}
	b, _ := io.ReadAll(io.LimitReader(httpResp.Body, 64*1024))
	return &Resp{
		Status: httpResp.StatusCode, Body: string(b),
		Location:  httpResp.Header.Get("Location"),
		SetCookie: capCookies(httpResp.Header["Set-Cookie"]),
		Elapsed:   time.Since(start),
	}, nil
}

// CookieHeader returns the agent's persisted session cookies for rawURL as a "name=v; name2=v2" string
// (empty if none / bad URL). It's how the authenticated session the agent established via send_request
// gets threaded into a dispatched OSS tool (ffuf/sqlmap): an authed IDOR/SQLi sweep MUST carry the login,
// else the tool hits the login wall and finds nothing (grounded on a live IDOR run — ffuf unauthenticated
// got a 302→/login for every id). Never persisted to vulnerabilities.json (the CapturedSession rule).
func (r *Requester) CookieHeader(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return mergeCookieHeader(r.jar.Cookies(u), "")
}

// mergeCookieHeader builds the outgoing Cookie header from the jar's persisted cookies plus an
// explicit Cookie header, where the EXPLICIT value overrides the jar for any shared name. This is
// what lets the agent forge/override a session token (Bearer <other-id>, a re-signed JWT) for an
// IDOR/privesc chain while still keeping the login cookie for names it did not override. Order:
// explicit names first (as given), then the jar names it did not replace.
func mergeCookieHeader(jarCookies []*http.Cookie, explicit string) string {
	var parts []string
	seen := map[string]bool{}
	// explicit "name=value; name2=value2" -- keep values VERBATIM (a forged token may contain '=' or a
	// space, e.g. "Bearer Mg=="), splitting only on the first '=' of each ';'-separated pair.
	if strings.TrimSpace(explicit) != "" {
		for _, pair := range strings.Split(explicit, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name := pair
			if i := strings.IndexByte(pair, '='); i >= 0 {
				name = strings.TrimSpace(pair[:i])
			}
			if name != "" && !seen[name] {
				seen[name] = true
				parts = append(parts, pair)
			}
		}
	}
	for _, c := range jarCookies {
		if !seen[c.Name] {
			seen[c.Name] = true
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
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
func indicators(payload, reqBody string, resp *Resp) []string {
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
	// SSTI: the arithmetic probe may live in the explicit `payload` (URL-param sinks) OR in the request
	// BODY (a POST form field / JSON param — Ruby ERB `<%= A*B %>`, a template sink behind a form). Check
	// both so a body-sink SSTI grounds without the agent having to duplicate the probe into `payload`.
	// A form body is URL-encoded (`<%=` → `%3C%25%3D`), so also scan a decoded copy. Still FP-free:
	// sstiEvaluated requires the >=4-digit product in the response and the raw expr absent.
	sstiHit := payload != "" && sstiEvaluated(payload, resp.Body)
	if !sstiHit && reqBody != "" {
		if sstiEvaluated(reqBody, resp.Body) {
			sstiHit = true
		} else if dec, err := url.QueryUnescape(reqBody); err == nil && sstiEvaluated(dec, resp.Body) {
			sstiHit = true
		}
	}
	if sstiHit {
		ind = append(ind, "ssti_eval") // server-side template injection: the engine COMPUTED the arithmetic probe
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

// sstiExprRe matches a template-injection ARITHMETIC probe in the payload — {{A*B}}, ${A*B},
// %{A*B}, <%= A*B %>, #{A*B} — the canonical SSTI/OGNL confirmation across Jinja/Twig/ERB/Freemarker/
// Ruby and Struts2 OGNL altSyntax (%{...}, grounded live on XBEN-035 where %{1234*1234} evaluated).
var sstiExprRe = regexp.MustCompile(`(?:\{\{|\$\{|%\{|<%=|#\{)\s*(\d{2,7})\s*\*\s*(\d{2,7})\s*(?:\}\}|\}|%>)`)

// sstiEvaluated reports a deterministic server-side-template-injection signal: the payload carried a
// template arithmetic expression whose PRODUCT appears in the response while the raw expression does
// NOT — i.e. the engine computed it (a mere reflection echoes the literal unchanged, which is XSS not
// SSTI). Requires a ≥4-digit product so a common small number can't collide, keeping ssti_eval
// false-positive-free (the record_finding gate requires it, and confirm_exploit re-verifies). Grounded
// (§10): a real request/response substring, never the model's reading.
func sstiEvaluated(payload, body string) bool {
	m := sstiExprRe.FindStringSubmatch(payload)
	if m == nil {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	if a == 0 || b == 0 {
		return false
	}
	product := strconv.Itoa(a * b)
	if len(product) < 4 {
		return false // too collision-prone to ground a finding
	}
	return strings.Contains(body, product) && !strings.Contains(body, m[0])
}

func hasIndicator(turn Turn, want string) bool {
	for _, i := range turn.Indicators {
		if i == want || strings.HasPrefix(i, want) {
			return true
		}
	}
	return false
}
