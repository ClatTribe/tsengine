package webagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// worldmodel.go is the offensive agent's STRUCTURED, EVIDENCE-GROUNDED world-model (ADR 0016 P1) — the
// XBOW long-horizon substrate that replaces reasoning over a scrolling, capped transcript with a durable
// structured index of the target: hosts, endpoints (+ their params + which classes were tested), the
// identities/sessions the agent holds, attempt outcomes, and (P3) host→host pivots.
//
// Grounding invariant (§10): the model is DERIVED from real evidence — Turns the agent actually sent/got
// and grounded Findings — never written by the LLM. BuildWorldModel is a pure function over (History,
// Findings); Digest renders it read-only for the prompt. A node that no Turn supports cannot exist, so the
// model can never introduce a false positive (record_finding still gates on a real indicator + cited turn).

// WorldModel is the structured target model. All maps/slices are derived; nothing here is authoritative
// beyond the evidence that produced it.
type WorldModel struct {
	Hosts      map[string]*WMHost     `json:"hosts"`
	Endpoints  map[string]*WMEndpoint `json:"endpoints"`
	Identities []*WMIdentity          `json:"identities,omitempty"`
	Attempts   []*WMAttempt           `json:"attempts,omitempty"`
	Edges      []*WMPivotEdge         `json:"edges,omitempty"` // host→host pivots (populated in P3)
}

// WMHost is one reachable host:port in the target's footprint (the cross-host graph's node).
type WMHost struct {
	ID        string   `json:"id"` // host[:port]
	Reachable bool     `json:"reachable"`
	Services  []string `json:"services,omitempty"` // "https" | "http" | "ssh" | …
	FromTurn  string   `json:"from_turn"`          // the evidence turn that discovered it
}

// WMEndpoint is one request surface, keyed by method + URL-shape (ids normalized so /items/1 ≡ /items/N).
type WMEndpoint struct {
	Host         string            `json:"host"`
	Method       string            `json:"method"`
	Shape        string            `json:"shape"`
	Params       []string          `json:"params,omitempty"`
	AuthRequired bool              `json:"auth_required,omitempty"`
	FromTurn     string            `json:"from_turn"`
	Tested       map[string]string `json:"tested,omitempty"` // class → outcome (confirmed|blocked)
}

// WMIdentity is a session/credential the agent holds — REDACTED to a fingerprint (never the live value,
// mirroring the CapturedSession rule that never persists a real session).
type WMIdentity struct {
	Kind        string `json:"kind"` // cookie | bearer | ssh
	Name        string `json:"name,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host,omitempty"`
	FromTurn    string `json:"from_turn"`
}

// WMAttempt is one (endpoint × class) outcome — the structured attempt memory (subsumes the pentest
// engMem's FailedAttempt). Confirmed comes from a grounded Finding; blocked from a real 403.
type WMAttempt struct {
	Endpoint string `json:"endpoint"`
	Class    string `json:"class,omitempty"`
	Outcome  string `json:"outcome"` // confirmed | blocked
	Turn     string `json:"turn"`
}

// WMPivotEdge is a host→host provenance edge (leaked cred / SSRF / source-disclosure opened another host).
type WMPivotEdge struct {
	FromHost string `json:"from_host"`
	ToHost   string `json:"to_host"`
	Via      string `json:"via"` // leaked-cred | ssrf | source-disclosure
	Evidence string `json:"evidence"`
}

// BuildWorldModel derives the world-model from the engagement's evidence — the request/response History
// and the grounded Findings. Pure + deterministic (the testable core). Every entity carries the evidence
// turn that produced it; nothing is invented.
func BuildWorldModel(turns []Turn, findings []Finding) *WorldModel {
	w := &WorldModel{Hosts: map[string]*WMHost{}, Endpoints: map[string]*WMEndpoint{}}
	for _, t := range turns {
		w.ingest(t)
	}
	// Grounded Findings mark a class CONFIRMED on their endpoint (explicit class — unambiguous, unlike a
	// shared raw indicator). Each finding cites the evidence turns.
	for _, f := range findings {
		ep := endpointKeyForRoute(f.Route)
		if e := w.Endpoints[ep]; e != nil && f.Class != "" {
			if e.Tested == nil {
				e.Tested = map[string]string{}
			}
			e.Tested[f.Class] = "confirmed"
		}
		turn := ""
		if len(f.Evidence) > 0 {
			turn = f.Evidence[0]
		}
		w.Attempts = append(w.Attempts, &WMAttempt{Endpoint: ep, Class: f.Class, Outcome: "confirmed", Turn: turn})
	}
	return w
}

// ingest folds one Turn into the model: its host, its endpoint (+ params + auth-requirement), any session
// identity it established, and a blocked-attempt if the server refused it (403).
func (w *WorldModel) ingest(t Turn) {
	host := hostPortOf(t.URL)
	if host != "" {
		h := w.Hosts[host]
		if h == nil {
			h = &WMHost{ID: host, Reachable: t.Status > 0, FromTurn: t.ID}
			w.Hosts[host] = h
		}
		if t.Status > 0 {
			h.Reachable = true
		}
		h.Services = addUnique(h.Services, schemeOf(t.URL))
	}

	shape := urlShape(t.URL)
	if shape != "" {
		method := strings.ToUpper(strings.TrimSpace(t.Method))
		if method == "" {
			method = "GET"
		}
		// a browser/oob pseudo-method (e.g. "GET(browser)") collapses to its verb for the surface model.
		if i := strings.IndexByte(method, '('); i > 0 {
			method = method[:i]
		}
		key := method + " " + shape
		e := w.Endpoints[key]
		if e == nil {
			e = &WMEndpoint{Host: host, Method: method, Shape: shape, FromTurn: t.ID}
			w.Endpoints[key] = e
		}
		for _, p := range queryParams(t.URL) {
			e.Params = addUnique(e.Params, p)
		}
		if t.Status == 401 {
			e.AuthRequired = true
		}
		if t.Status == 403 { // the server actively refused — a defense/block on this endpoint
			if e.Tested == nil {
				e.Tested = map[string]string{}
			}
			w.Attempts = append(w.Attempts, &WMAttempt{Endpoint: key, Outcome: "blocked", Turn: t.ID})
		}
	}

	for _, sc := range t.SetCookies {
		name := cookieName(sc)
		if !looksLikeSession(name) {
			continue
		}
		w.Identities = append(w.Identities, &WMIdentity{
			Kind: "cookie", Name: name, Fingerprint: fingerprint(sc), Host: host, FromTurn: t.ID,
		})
	}
}

// Digest renders the world-model as a compact, LLM-readable summary — the read-only view the prompt shows
// so the agent reasons over structure, not a scrolling transcript. Deterministic (sorted).
func (w *WorldModel) Digest() string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	// Hosts + pivots
	hosts := make([]string, 0, len(w.Hosts))
	for id := range w.Hosts {
		hosts = append(hosts, id)
	}
	sort.Strings(hosts)
	if len(hosts) > 0 {
		fmt.Fprintf(&b, "HOSTS (%d): %s\n", len(hosts), strings.Join(hosts, ", "))
	}
	for _, e := range w.Edges {
		fmt.Fprintf(&b, "  PIVOT %s -> %s (via %s)\n", e.FromHost, e.ToHost, e.Via)
	}
	// Endpoints
	keys := make([]string, 0, len(w.Endpoints))
	for k := range w.Endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		fmt.Fprintf(&b, "ENDPOINTS (%d):\n", len(keys))
		for _, k := range keys {
			e := w.Endpoints[k]
			line := "  " + k
			if len(e.Params) > 0 {
				ps := append([]string(nil), e.Params...)
				sort.Strings(ps)
				line += " ?" + strings.Join(ps, ",")
			}
			if e.AuthRequired {
				line += " [auth]"
			}
			if len(e.Tested) > 0 {
				var ts []string
				for c, o := range e.Tested {
					ts = append(ts, c+"="+o)
				}
				sort.Strings(ts)
				line += " {" + strings.Join(ts, ",") + "}"
			}
			b.WriteString(line + "\n")
		}
	}
	// Identities (redacted)
	if len(w.Identities) > 0 {
		var ids []string
		for _, id := range w.Identities {
			ids = append(ids, fmt.Sprintf("%s:%s", id.Name, id.Fingerprint))
		}
		sort.Strings(ids)
		fmt.Fprintf(&b, "SESSIONS HELD (%d): %s\n", len(w.Identities), strings.Join(ids, ", "))
	}
	// Blocked endpoints (don't re-try these blindly)
	var blocked []string
	for _, a := range w.Attempts {
		if a.Outcome == "blocked" {
			blocked = addUnique(blocked, a.Endpoint)
		}
	}
	if len(blocked) > 0 {
		sort.Strings(blocked)
		fmt.Fprintf(&b, "BLOCKED (WAF/403 — needs obfuscation or is a dead end): %s\n", strings.Join(blocked, "; "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- pure helpers ---

var idSeg = regexp.MustCompile(`^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$`)

// urlShape normalizes a URL to method-agnostic surface shape: scheme+host+path with numeric/hex/uuid path
// segments collapsed to ":id" (so /items/1 ≡ /items/42), query dropped (param NAMES ride the endpoint).
func urlShape(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if idSeg.MatchString(s) {
			segs[i] = ":id"
		}
	}
	path := strings.Join(segs, "/")
	if path == "" {
		path = "/"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path
}

// endpointKeyForRoute builds an endpoint key from a finding's Route (method unknown → GET default, matching
// how most routes are recorded).
func endpointKeyForRoute(route string) string {
	shape := urlShape(route)
	if shape == "" {
		return ""
	}
	return "GET " + shape
}

func hostPortOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

func schemeOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

func queryParams(raw string) []string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	var out []string
	for k := range u.Query() {
		out = append(out, k)
	}
	return out
}

// looksLikeSession is a conservative name filter for a session cookie (so a CSRF/pref cookie isn't logged
// as a held session).
func looksLikeSession(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"session", "sess", "sid", "token", "auth", "jwt", "phpsessid", "connect.sid"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// fingerprint is a short, non-reversible digest of a secret value (so the model shows a session is HELD
// without persisting the token).
func fingerprint(raw string) string {
	v := raw
	if i := strings.IndexByte(raw, '='); i >= 0 && i+1 < len(raw) {
		v = raw[i+1:]
	}
	if j := strings.IndexByte(v, ';'); j >= 0 {
		v = v[:j]
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(v)))
	return hex.EncodeToString(sum[:])[:8]
}

func addUnique(xs []string, x string) []string {
	x = strings.TrimSpace(x)
	if x == "" {
		return xs
	}
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}
