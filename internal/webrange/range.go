// Package webrange is an emulated, procedurally-generated vulnerable web
// application used to test the web agent (internal/webagent) against an
// INDEPENDENT ground-truth answer key — the web analog of the cloud agent's
// procedural dataset + CloudGoat harness.
//
// The point is anti-circularity. A range mixes real, exploitable routes with
// DECOYS: routes that look injectable (reflect input, accept a redirect param,
// take a filename, run a "ping") but are safe (escape output, allowlist the
// redirect, sanitise the path, shell-escape the arg). A blind attacker probes
// every route the same way; only the real vulns emit a deterministic indicator,
// so the engine's grounding gate — not the attacker's guesswork — decides what is
// recorded. Recall measures whether the agent finds the real ones; the decoy count
// measures whether grounding holds (a circular detector would "confirm" the decoys
// too).
package webrange

import (
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Vuln classes (mirror webagent's grounded classes).
const (
	ClassSQLi     = "sqli"
	ClassXSS      = "xss"
	ClassRedirect = "open_redirect"
	ClassPathTrav = "path_traversal"
	ClassCmdi     = "command_injection"
)

var allClasses = []string{ClassSQLi, ClassXSS, ClassRedirect, ClassPathTrav, ClassCmdi}

// Target is one planted route — a Manifest entry (the answer key).
type Target struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Param       string `json:"param"`
	Class       string `json:"class"`       // the apparent vuln class
	Exploitable bool   `json:"exploitable"` // true = real; false = decoy (safe sibling)
	WAF         bool   `json:"waf"`         // exploitable but a naive filter blocks the obvious payload
}

// Manifest is the ground-truth answer key for a generated range.
type Manifest struct {
	Seed        int64    `json:"seed"`
	Targets     []Target `json:"targets"`
	Exploitable int      `json:"exploitable_count"`
	Decoys      int      `json:"decoy_count"`
}

// Range is the emulated app (an http.Handler) plus its answer key.
type Range struct {
	Manifest Manifest
	mux      *http.ServeMux
}

// Opts tune generation.
type Opts struct {
	N         int     // number of param-bearing routes (default 12)
	DecoyFrac float64 // fraction that are decoys (default 0.4)
	WAFFrac   float64 // fraction of exploitable routes behind a naive WAF (default 0.2)
	Noise     int     // static, param-less routes the agent should ignore (default 4)
}

func (o *Opts) defaults() {
	if o.N <= 0 {
		o.N = 12
	}
	if o.DecoyFrac <= 0 {
		o.DecoyFrac = 0.4
	}
	if o.WAFFrac <= 0 {
		o.WAFFrac = 0.2
	}
	if o.Noise <= 0 {
		o.Noise = 4
	}
}

var nouns = []string{
	"product", "user", "order", "invoice", "report", "profile", "search", "page",
	"article", "comment", "ticket", "session", "document", "account", "item", "event",
	"file", "image", "redirect", "host", "lookup", "query", "view", "node",
}

// paramFor returns the conventional parameter name for a class (so the surface
// looks realistic), with a disambiguating suffix when needed.
func paramFor(class string, r *rand.Rand) string {
	base := map[string]string{
		ClassSQLi:     "id",
		ClassXSS:      "q",
		ClassRedirect: "next",
		ClassPathTrav: "file",
		ClassCmdi:     "host",
	}[class]
	if r.Intn(2) == 0 {
		return base
	}
	alt := map[string]string{
		ClassSQLi:     "uid",
		ClassXSS:      "name",
		ClassRedirect: "url",
		ClassPathTrav: "path",
		ClassCmdi:     "target",
	}[class]
	return alt
}

// Generate builds a deterministic range from seed.
func Generate(seed int64, opts Opts) *Range {
	opts.defaults()
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // not security-sensitive; reproducible fixtures
	rg := &Range{mux: http.NewServeMux()}
	rg.Manifest.Seed = seed

	used := map[string]bool{}
	uniquePath := func() string {
		for {
			p := "/" + nouns[r.Intn(len(nouns))]
			if r.Intn(2) == 0 {
				p += "/" + nouns[r.Intn(len(nouns))]
			}
			if !used[p] {
				used[p] = true
				return p
			}
		}
	}

	for i := 0; i < opts.N; i++ {
		class := allClasses[i%len(allClasses)]
		// shuffle class a bit so it isn't a fixed rotation
		if r.Intn(3) == 0 {
			class = allClasses[r.Intn(len(allClasses))]
		}
		t := Target{
			ID:          fmt.Sprintf("wr-%02d", i),
			Path:        uniquePath(),
			Param:       paramFor(class, r),
			Class:       class,
			Exploitable: r.Float64() >= opts.DecoyFrac,
		}
		if t.Exploitable && r.Float64() < opts.WAFFrac {
			t.WAF = true
		}
		rg.Manifest.Targets = append(rg.Manifest.Targets, t)
		rg.register(t)
	}

	// static, param-less noise routes (no vuln; agent should ignore)
	for i := 0; i < opts.Noise; i++ {
		p := uniquePath()
		body := fmt.Sprintf("<html><body><h1>%s</h1><p>static content</p></body></html>", strings.TrimPrefix(p, "/"))
		rg.mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
	}

	// index lists the surface (a crawler/recon would find these)
	surface := rg.Surface()
	rg.mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		var b strings.Builder
		b.WriteString("<html><body><h1>webrange</h1><ul>")
		for _, s := range surface {
			fmt.Fprintf(&b, `<li><a href="%s1">%s</a></li>`, s, s)
		}
		b.WriteString("</ul></body></html>")
		fmt.Fprint(w, b.String())
	})

	for _, t := range rg.Manifest.Targets {
		if t.Exploitable {
			rg.Manifest.Exploitable++
		} else {
			rg.Manifest.Decoys++
		}
	}
	return rg
}

// Handler is the emulated app (mount in httptest.NewServer).
func (rg *Range) Handler() http.Handler { return rg.mux }

// Surface returns the param-bearing routes as relative "path?param=" strings
// (what a recon crawl would hand the agent). Sorted for determinism.
func (rg *Range) Surface() []string {
	var s []string
	for _, t := range rg.Manifest.Targets {
		s = append(s, t.Path+"?"+t.Param+"=")
	}
	sort.Strings(s)
	return s
}

// register wires the planted behaviour for one target.
func (rg *Range) register(t Target) {
	rg.mux.HandleFunc(t.Path, func(w http.ResponseWriter, req *http.Request) {
		v := req.URL.Query().Get(t.Param)
		switch t.Class {
		case ClassSQLi:
			serveSQLi(w, v, t)
		case ClassXSS:
			serveXSS(w, v, t)
		case ClassRedirect:
			serveRedirect(w, req, v, t)
		case ClassPathTrav:
			servePathTrav(w, v, t)
		case ClassCmdi:
			serveCmdi(w, v, t)
		}
	})
}

// --- planted behaviours (exploitable) and their safe siblings (decoys) ---

var dbErrors = []string{
	"You have an error in your SQL syntax near '%s' at line 1",
	"pg_query(): Query failed: ERROR: syntax error at or near \"%s\"",
	"Warning: SQLITE_ERROR: unrecognized token: \"%s\"",
	"ORA-00933: SQL command not properly ended near %s",
}

func serveSQLi(w http.ResponseWriter, v string, t Target) {
	if t.Exploitable && strings.ContainsAny(v, "'\"") {
		w.WriteHeader(http.StatusInternalServerError)
		// deterministic error choice from the path. The echoed fragment is escaped
		// (as a real framework error page is) so the page leaks a DB error WITHOUT
		// also being a raw reflection — the sql_error indicator is the only signal.
		idx := int(t.Path[len(t.Path)-1]) % len(dbErrors)
		fmt.Fprintf(w, dbErrors[idx], html.EscapeString(v))
		return
	}
	fmt.Fprintf(w, "<div>result for %s</div>", html.EscapeString(v)) // decoy: parameterised, safe echo
}

func serveXSS(w http.ResponseWriter, v string, t Target) {
	if t.WAF && strings.Contains(strings.ToLower(v), "<script") {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "blocked by WAF")
		return
	}
	if t.Exploitable {
		fmt.Fprintf(w, "<div>Hello, %s!</div>", v) // raw reflection
		return
	}
	fmt.Fprintf(w, "<div>Hello, %s!</div>", html.EscapeString(v)) // decoy: escaped
}

func serveRedirect(w http.ResponseWriter, req *http.Request, v string, t Target) {
	if t.Exploitable {
		http.Redirect(w, req, v, http.StatusFound) // open: redirects anywhere
		return
	}
	// decoy: only same-origin paths; an external/absolute URL is refused.
	if u, err := url.Parse(v); err != nil || u.Host != "" || !strings.HasPrefix(v, "/") {
		http.Redirect(w, req, "/home", http.StatusFound)
		return
	}
	http.Redirect(w, req, v, http.StatusFound)
}

func servePathTrav(w http.ResponseWriter, v string, t Target) {
	if t.Exploitable && strings.Contains(v, "..") {
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		return
	}
	clean := strings.ReplaceAll(v, "..", "") // decoy: strips traversal
	if clean == "" || strings.Contains(v, "..") {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "file not found")
		return
	}
	fmt.Fprintf(w, "contents of %s", html.EscapeString(clean))
}

func serveCmdi(w http.ResponseWriter, v string, t Target) {
	if t.Exploitable && strings.ContainsAny(v, ";|&") {
		fmt.Fprint(w, "PING 127.0.0.1: 56 data bytes\nuid=0(root) gid=0(root) groups=0(root)\n")
		return
	}
	fmt.Fprintf(w, "PING %s ok", html.EscapeString(v)) // decoy: arg is escaped, no shell
}
