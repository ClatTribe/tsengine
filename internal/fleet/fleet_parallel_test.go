package fleet

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// --- Phase C: the bounded-parallel coordinator (ADR 0030 D5) ---

// benignTarget answers 200 "ok" to everything, so a quote-payload attempt grounds a Clean and
// nothing else fires.
func benignTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})
	return httptest.NewServer(mux)
}

func cleanScript(base, path string) []string {
	return []string{
		fmt.Sprintf(`{"tool":"send_request","args":{"method":"GET","url":%q,"payload":"'"}}`, base+path+"?q='"),
		`{"tool":"finish","args":{"summary":"attempted, nothing fired"}}`,
	}
}

// TestRunFleet_DisjointChunksShareAWaveAndBothRun: two independent chunks run concurrently (one
// wave), both reports land, both verdicts enter the worldview.
func TestRunFleet_DisjointChunksShareAWaveAndBothRun(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	in := FrontierInput{
		Target: srv.URL,
		Seeds: []webagent.SeedFinding{
			{Route: srv.URL + "/a?q=1", Class: "sqli", Severity: "high"},
			{Route: srv.URL + "/b?q=1", Class: "xss", Severity: "medium"},
		},
	}
	res, err := RunFleet(context.Background(), nil,
		srv.URL, in, webagent.Options{MaxIters: 6, MaxRequests: 30}, Config{
			Workers: 2,
			NewWorkerLLM: func(chunkID string) cloudengine.LLM {
				p := "/a"
				if strings.HasSuffix(chunkID, "0002") {
					p = "/b"
				}
				return &scriptLLM{steps: cleanScript(srv.URL, p)}
			},
		})
	if err != nil {
		t.Fatalf("RunFleet: %v", err)
	}
	if res.Waves != 1 {
		t.Errorf("two route-disjoint chunks must share one wave, got %d", res.Waves)
	}
	if len(res.Reports) != 2 {
		t.Fatalf("both chunks must run, got %d report(s); disclosures: %v", len(res.Reports), res.Disclosures)
	}
	if v, ok := res.Worldview.Get(routeID(srv.URL+"/a"), "sqli"); !ok || v.Verdict != Clean {
		t.Errorf("worldview missing grounded Clean for sqli on /a:\n%s", res.Ledger())
	}
	if _, ok := res.Worldview.Get(routeID(srv.URL+"/b"), "xss"); !ok {
		t.Errorf("worldview missing xss on /b:\n%s", res.Ledger())
	}
}

// TestRunFleet_EnvelopeBoundsTotalRequests is the user-visible form of the absolute-wall invariant:
// with a tight engagement envelope, the COMBINED sends of all workers never exceed it.
func TestRunFleet_EnvelopeBoundsTotalRequests(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	in := FrontierInput{
		Target: srv.URL,
		Seeds: []webagent.SeedFinding{
			{Route: srv.URL + "/a?q=1", Class: "sqli", Severity: "high"},
			{Route: srv.URL + "/b?q=1", Class: "xss", Severity: "medium"},
		},
	}
	// Each worker's script tries 4 sends; the envelope allows 4 TOTAL.
	spam := func(p string) []string {
		steps := []string{}
		for i := 0; i < 4; i++ {
			steps = append(steps, fmt.Sprintf(`{"tool":"send_request","args":{"method":"GET","url":%q}}`, srv.URL+p))
		}
		return append(steps, `{"tool":"finish","args":{"summary":"done"}}`)
	}
	res, err := RunFleet(context.Background(), nil, srv.URL, in,
		webagent.Options{MaxIters: 12, MaxRequests: 50}, Config{
			Workers: 2, TotalRequests: 4,
			NewWorkerLLM: func(chunkID string) cloudengine.LLM {
				p := "/a"
				if strings.HasSuffix(chunkID, "0002") {
					p = "/b"
				}
				return &scriptLLM{steps: spam(p)}
			},
		})
	if err != nil {
		t.Fatalf("RunFleet: %v", err)
	}
	total := 0
	for _, r := range res.Reports {
		total += r.Coverage.RequestsSent
	}
	if total > 4 {
		t.Errorf("combined sends (%d) exceeded the engagement envelope (4)", total)
	}
	if total == 0 {
		t.Error("the envelope must still ALLOW work, not zero it out")
	}
}

// TestRunFleet_PreTrippedGovernorHaltsEverything: a latched fleet breaker halts before any worker
// runs, and the disclosure names what did not.
func TestRunFleet_PreTrippedGovernorHaltsEverything(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	gov := NewGovernor(EnvelopeConfig{MaxRequests: 100, Window: time.Minute})
	gov.Record(SessionInvalid)
	gov.Record(SessionInvalid)
	gov.Record(SessionInvalid) // trips at 3
	if tripped, _ := gov.Tripped(); !tripped {
		t.Fatal("governor must be tripped for this test")
	}
	in := FrontierInput{
		Target: srv.URL,
		Seeds:  []webagent.SeedFinding{{Route: srv.URL + "/a?q=1", Class: "sqli", Severity: "high"}},
	}
	res, err := RunFleet(context.Background(), &scriptLLM{}, srv.URL, in,
		webagent.Options{MaxIters: 5, MaxRequests: 20}, Config{Governor: gov})
	if err != nil {
		t.Fatalf("RunFleet: %v", err)
	}
	if len(res.Reports) != 0 {
		t.Errorf("a tripped governor must halt before spawning workers, ran %d", len(res.Reports))
	}
	if len(res.Disclosures) == 0 || !strings.Contains(strings.Join(res.Disclosures, " "), "auto-halt latched") {
		t.Errorf("the halt must be disclosed with its reason, got %v", res.Disclosures)
	}
}

// TestRunFleet_SkipsSettledVerdicts is frontier monotonicity (D5): a chunk whose declared
// route×class already holds a verdict at CoverK is skipped — budget spent once, skip disclosed.
func TestRunFleet_SkipsSettledVerdicts(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	in := FrontierInput{
		Target: srv.URL,
		Seeds: []webagent.SeedFinding{
			{Route: srv.URL + "/x?q=1", Class: "sqli", Severity: "critical", Enrichment: "KEV"}, // ranks first
			{Route: srv.URL + "/x?q=1", Class: "sqli", Severity: "high"},                        // same route×class → settled after #1
		},
	}
	res, err := RunFleet(context.Background(),
		&scriptLLM{steps: cleanScript(srv.URL, "/x")},
		srv.URL, in, webagent.Options{MaxIters: 6, MaxRequests: 30}, Config{Workers: 1, CoverK: 1})
	if err != nil {
		t.Fatalf("RunFleet: %v", err)
	}
	if len(res.Reports) != 1 {
		t.Errorf("only the first look should run at CoverK=1, got %d report(s)", len(res.Reports))
	}
	if len(res.SkippedChunks) != 1 {
		t.Errorf("the settled chunk must be skipped + named, got %v", res.SkippedChunks)
	}
	v, ok := res.Worldview.Get(routeID(srv.URL+"/x"), "sqli")
	if !ok || v.Verdict != Clean {
		t.Errorf("expected a grounded Clean from the attempt, got %+v ok=%v", v, ok)
	}
}

// TestRunFleet_StallWatchdogHaltsSpending (D5 vector 6): waves that keep producing no verdicts
// terminate the run with an honest disclosure instead of burning the envelope.
func TestRunFleet_StallWatchdogHaltsSpending(t *testing.T) {
	srv := benignTarget()
	defer srv.Close()
	// Three general chunks over the SAME route → three waves (route-coupled), each producing no
	// verdicts (general chunks ground only Vulnerable-from-findings; none here).
	in := FrontierInput{
		Target:     srv.URL,
		Discovered: []string{srv.URL + "/x?q=1"},
	}
	// Decompose yields ONE residual chunk for /x. Force three waves by seeding two more chunks on
	// the same route as general looks via Leads (Class=="").
	in.Leads = []webagent.EstateLead{
		{Route: srv.URL + "/x?q=1", Reaches: "crown"},
	}
	// residual + crown + … need a third: add another lead (same route).
	in.Leads = append(in.Leads, webagent.EstateLead{Route: srv.URL + "/x?q=2", Reaches: "crown2"})
	finish := `{"tool":"finish","args":{"summary":"nothing"}}`
	script := []string{finish, finish, finish, finish} // every worker finishes immediately
	res, err := RunFleet(context.Background(), &scriptLLM{steps: script}, srv.URL, in,
		webagent.Options{MaxIters: 3, MaxRequests: 30}, Config{Workers: 1, StaleWaves: 1})
	if err != nil {
		t.Fatalf("RunFleet: %v", err)
	}
	if len(res.Reports) >= 3 {
		t.Errorf("the watchdog must halt before later stale waves run, ran %d chunk(s)", len(res.Reports))
	}
	joined := strings.Join(res.Disclosures, " ")
	if !strings.Contains(joined, "stall watchdog") {
		t.Errorf("the stall halt must be disclosed, got %v", res.Disclosures)
	}
	if !strings.Contains(joined, "not run") {
		t.Errorf("the disclosure must name what did not run, got %v", res.Disclosures)
	}
}

// --- helpers ---
