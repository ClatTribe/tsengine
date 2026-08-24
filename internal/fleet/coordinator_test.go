package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// scriptLLM returns a fixed sequence of JSON actions, ignoring the prompt — drives the real webagent
// loop deterministically with no API key. Exhausted → finish (loop terminates).
type scriptLLM struct {
	steps []string
	i     int
}

func (s *scriptLLM) Generate(_ context.Context, _ string) (string, error) {
	if s.i >= len(s.steps) {
		return `{"tool":"finish","args":{"summary":"out of script"}}`, nil
	}
	out := s.steps[s.i]
	s.i++
	return out, nil
}

// sqliTarget: any quote in ?q= elicits a database error string (grounds a sqli finding).
func sqliTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.ContainsAny(q, "'\"") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "You have an error in your SQL syntax near '%s' at line 1", q)
			return
		}
		fmt.Fprintf(w, "results for %s", q)
	})
	return httptest.NewServer(mux)
}

func sqliScript(base string) []string {
	return []string{
		fmt.Sprintf(`{"thought":"probe","tool":"send_request","args":{"method":"GET","url":%q,"payload":"'"}}`, base+"/search?q='"),
		fmt.Sprintf(`{"thought":"record","tool":"record_finding","args":{"route":%q,"class":"sqli","severity":"high","evidence":["t-001"],"rationale":"error-based SQLi"}}`, base+"/search"),
		`{"thought":"done","tool":"finish","args":{"summary":"proved error-based SQLi on /search"}}`,
	}
}

// TestFleet_SingleWorkerMatchesDirectInvestigate is the STRANGLER GUARANTEE (ADR 0030 D2): a
// 1-worker fleet's report is byte-identical to calling webagent.Investigate directly. The coordinator
// may ADD a worldview; it may not ALTER the engagement.
func TestFleet_SingleWorkerMatchesDirectInvestigate(t *testing.T) {
	srv := sqliTarget()
	defer srv.Close()
	script := sqliScript(srv.URL)
	opts := webagent.Options{MaxIters: 10, MaxRequests: 20}

	// Direct.
	ccA := &webagent.Context{Target: srv.URL}
	reportA, err := webagent.Investigate(context.Background(), &scriptLLM{steps: script}, ccA, opts)
	if err != nil {
		t.Fatalf("direct Investigate: %v", err)
	}
	// Via the fleet coordinator (fresh brain + context, same script/target/opts).
	ccB := &webagent.Context{Target: srv.URL}
	res, err := RunSingle(context.Background(), &scriptLLM{steps: sqliScript(srv.URL)}, ccB, opts)
	if err != nil {
		t.Fatalf("RunSingle: %v", err)
	}

	ja, _ := json.Marshal(reportA)
	jb, _ := json.Marshal(res.Report)
	if string(ja) != string(jb) {
		t.Errorf("1-worker fleet report differs from direct Investigate:\n direct=%s\n fleet =%s", ja, jb)
	}
}

// The worldview is built from the same run and holds the proven finding as a Vulnerable, evidence-
// cited, Canonical-routed claim.
func TestFleet_WorldviewFromFindings(t *testing.T) {
	srv := sqliTarget()
	defer srv.Close()
	cc := &webagent.Context{Target: srv.URL}
	res, err := RunSingle(context.Background(), &scriptLLM{steps: sqliScript(srv.URL)}, cc, webagent.Options{MaxIters: 10, MaxRequests: 20})
	if err != nil {
		t.Fatalf("RunSingle: %v", err)
	}
	if len(res.Report.Findings) == 0 {
		t.Fatalf("expected a proven sqli finding, got none (summary: %q)", res.Report.Summary)
	}
	route := estategraph.Canonical(surfaceWeb, srv.URL+"/search")
	v, ok := res.Worldview.Get(route, "sqli")
	if !ok || v.Verdict != Vulnerable {
		t.Fatalf("worldview must carry sqli=Vulnerable on %s, got %+v ok=%v", route, v, ok)
	}
	if len(v.Evidence) == 0 {
		t.Error("the Vulnerable verdict must cite its evidence turns")
	}
	// The route shares the estate identity space (Canonical), not a raw URL.
	if strings.Contains(route, srv.URL) && !strings.HasPrefix(route, "web:") {
		t.Errorf("route must be a Canonical id, got %q", route)
	}
	// Ledger renders it.
	if l := res.Ledger(); !strings.Contains(l, "sqli: vulnerable") {
		t.Errorf("ledger must show the proven class:\n%s", l)
	}
}

// A degenerate engagement (no findings) yields an empty-but-valid worldview and an honest ledger that
// names known routes as having NO verdict — never as clean.
func TestFleet_NoFindingsIsHonest(t *testing.T) {
	srv := sqliTarget()
	defer srv.Close()
	// Script that probes a benign path and finds nothing.
	script := []string{
		fmt.Sprintf(`{"thought":"probe","tool":"send_request","args":{"method":"GET","url":%q}}`, srv.URL+"/search?q=hello"),
		`{"thought":"done","tool":"finish","args":{"summary":"nothing found"}}`,
	}
	cc := &webagent.Context{Target: srv.URL}
	res, err := RunSingle(context.Background(), &scriptLLM{steps: script}, cc, webagent.Options{MaxIters: 10, MaxRequests: 20})
	if err != nil {
		t.Fatalf("RunSingle: %v", err)
	}
	if len(res.Worldview.Verdicts()) != 0 {
		t.Errorf("no findings → no verdicts, got %d", len(res.Worldview.Verdicts()))
	}
	l := res.Ledger()
	if strings.Contains(l, "clean") {
		t.Errorf("a run with no findings must NEVER report a route clean:\n%s", l)
	}
	if !strings.Contains(l, "NO established verdict") {
		t.Errorf("known-but-unproven routes must be named as no-verdict:\n%s", l)
	}
}
