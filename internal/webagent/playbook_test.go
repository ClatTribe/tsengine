package webagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// playbookBrain is a deterministic stand-in for the LLM brain. It executes a
// GENERIC attacker playbook — for each known route it tries canonical payloads,
// reads the engine's reported INDICATORS from the transcript, adapts past a WAF,
// and records ONLY what the indicators prove (the engine's grounding gate is what
// actually decides). It has NO foreknowledge of which routes are vulnerable.
//
// It lets us run the REAL Investigate loop against a REAL multi-vuln HTTP server
// end-to-end when the paid LLM is unavailable — same cloudengine.LLM interface,
// same loop, same grounding, same scoring.
type playbookBrain struct {
	probes  []probe
	pi      int
	lastIdx int // probe index of the send we're awaiting an observation for (-1 = none)

	phase     int // 0=probe 1=record 2=confirm 3=finish
	noteQueue []string
	pending   []pendRec
	confirm   []string
	findN     int
}

type probe struct{ url, payload, class, indicator string }
type pendRec struct {
	turnID, url, class string
}

// q builds a properly URL-encoded probe URL — the payload value is escaped in the
// query (as a real client/LLM would), while the raw payload is kept for the
// engine's reflection check (indicators() looks for the DECODED value in the body).
func q(base, path, param, payload string) string {
	return base + path + "?" + param + "=" + url.QueryEscape(payload)
}

func newPlaybook(base string) *playbookBrain {
	return &playbookBrain{
		lastIdx: -1,
		probes: []probe{
			{q(base, "/product", "id", "'"), "'", "sqli", "sql_error"},
			{q(base, "/greet", "name", "<script>alert(1)</script>"), "<script>alert(1)</script>", "xss", "reflected_input"},             // WAF will block this
			{q(base, "/greet", "name", "\"><img src=x onerror=alert(1)>"), "\"><img src=x onerror=alert(1)>", "xss", "reflected_input"}, // adapted vector
			{q(base, "/out", "next", "http://evil.test/"), "http://evil.test/", "open_redirect", "external_redirect"},
		},
	}
}

var obsRe = regexp.MustCompile(`t-(\d{3})\s+status=\d+\s+indicators=\[([^\]]*)\]`)

// latestObs extracts the turn id + indicator list of the most recent send.
func latestObs(prompt string) (turnID, inds string) {
	m := obsRe.FindAllStringSubmatch(prompt, -1)
	if len(m) == 0 {
		return "", ""
	}
	last := m[len(m)-1]
	return "t-" + last[1], last[2]
}

func act(tool string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"thought": "playbook", "tool": tool, "args": args})
	return string(b)
}

func (b *playbookBrain) Generate(_ context.Context, prompt string) (string, error) {
	// 1) Correlate the observation for the send we just made.
	if b.lastIdx >= 0 {
		tid, inds := latestObs(prompt)
		p := b.probes[b.lastIdx]
		if tid != "" {
			if strings.Contains(inds, "blocked_") {
				b.noteQueue = append(b.noteQueue, "WAF blocked a payload on "+p.url)
			}
			if strings.Contains(inds, p.indicator) {
				b.pending = append(b.pending, pendRec{tid, p.url, p.class})
			}
		}
		b.lastIdx = -1
	}

	// 2) Flush any WAF observations (exercises note_defense).
	if len(b.noteQueue) > 0 {
		sig := b.noteQueue[0]
		b.noteQueue = b.noteQueue[1:]
		return act("note_defense", map[string]any{"signature": sig}), nil
	}

	switch b.phase {
	case 0: // PROBE: walk the playbook
		if b.pi < len(b.probes) {
			p := b.probes[b.pi]
			b.lastIdx = b.pi
			b.pi++
			args := map[string]any{"method": "GET", "url": p.url}
			if p.payload != "" {
				args["payload"] = p.payload
			}
			return act("send_request", args), nil
		}
		b.phase = 1
		fallthrough
	case 1: // RECORD: commit the indicator-proven findings (grounded)
		if len(b.pending) > 0 {
			r := b.pending[0]
			b.pending = b.pending[1:]
			b.findN++
			b.confirm = append(b.confirm, fmt.Sprintf("web-%03d", b.findN))
			return act("record_finding", map[string]any{
				"route": r.url, "class": r.class, "evidence": []any{r.turnID},
				"severity": "high", "rationale": "indicator-proven by the playbook",
			}), nil
		}
		b.phase = 2
		fallthrough
	case 2: // CONFIRM: re-fire each proof in isolation
		if len(b.confirm) > 0 {
			id := b.confirm[0]
			b.confirm = b.confirm[1:]
			return act("confirm_exploit", map[string]any{"finding_id": id}), nil
		}
		b.phase = 3
		fallthrough
	default: // FINISH
		return act("finish", map[string]any{"summary": "playbook engagement complete"}), nil
	}
}

// multiVulnTarget plants three real, distinct vulns + a naive WAF, so the agent
// must discover them via indicators and adapt past the filter.
func multiVulnTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/product", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Database error: You have an error in your SQL syntax near '%s' at line 1", id)
			return
		}
		fmt.Fprintf(w, "<h1>Product %s</h1>", id)
	})
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(strings.ToLower(name), "<script") { // naive WAF
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "blocked by WAF")
			return
		}
		fmt.Fprintf(w, "<div>Hello, %s!</div>", name) // raw reflection (img/svg vectors pass)
	})
	mux.HandleFunc("/out", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	return httptest.NewServer(mux)
}

func TestInvestigate_PlaybookDiscoversAllThree(t *testing.T) {
	srv := multiVulnTarget()
	defer srv.Close()

	cc := &Context{
		Target: srv.URL,
		Routes: []string{srv.URL + "/product?id=", srv.URL + "/greet?name=", srv.URL + "/out?next="},
	}
	rep, err := Investigate(context.Background(), newPlaybook(srv.URL), cc, Options{MaxRequests: 60, MaxIters: 40})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// Honest scoring against the answer key (route -> expected class).
	key := map[string]string{
		q(srv.URL, "/product", "id", "'"):                               "sqli",
		q(srv.URL, "/greet", "name", "\"><img src=x onerror=alert(1)>"): "xss",
		q(srv.URL, "/out", "next", "http://evil.test/"):                 "open_redirect",
	}
	sc := rep.ScoreAgainst(key)

	t.Log("\n" + Render(rep))
	t.Logf("score: recall=%.0f%% (%d/%d) invented=%d pass=%v", sc.Recall*100, sc.RealFound, sc.RealTotal, sc.Invented, sc.Pass)

	if !sc.Pass {
		t.Fatalf("expected all 3 classes found, 0 invented; got %+v missed=%v", sc, sc.Missed)
	}
	// Every recorded finding must be Verified (confirm_exploit reproduced the indicator).
	for _, f := range rep.Findings {
		if !f.Verified {
			t.Errorf("finding %s (%s) not Verified", f.ID, f.Class)
		}
	}
	// The WAF must have been encountered AND bypassed: the recorded XSS rode the
	// adapted img-vector turn, not the blocked <script> turn.
	var xssCount int
	for _, f := range rep.Findings {
		if f.Class == "xss" {
			xssCount++
		}
	}
	if xssCount != 1 {
		t.Errorf("want exactly 1 grounded XSS (the adapted vector), got %d", xssCount)
	}
}
