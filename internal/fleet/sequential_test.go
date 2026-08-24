package fleet

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ClatTribe/tsengine/internal/webagent"
)

// flakySqliTarget models the real cause of worker disagreement: variance. The FIRST quote-bearing
// request to /x elicits a SQL error (looks vulnerable); every later one is clean. Two workers probing
// the same route with the same payload therefore reach opposite verdicts — exactly the case the
// worldview must render Contested, not clobber.
func flakySqliTarget() *httptest.Server {
	var mu sync.Mutex
	fired := false
	mux := http.NewServeMux()
	mux.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		mu.Lock()
		first := !fired
		if strings.Contains(q, "'") && !fired {
			fired = true
		}
		mu.Unlock()
		if strings.Contains(q, "'") && first {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "You have an error in your SQL syntax near ''")
			return
		}
		fmt.Fprint(w, "ok")
	})
	return httptest.NewServer(mux)
}

// TestFleet_SequentialContestedNotClobbered is the ADR's named Phase B test: two sequential workers
// over overlapping chunks (both "sqli on /x") disagree — one proves it, one attempts it and finds
// nothing — and the worldview records Contested, keeping BOTH sides' evidence.
func TestFleet_SequentialContestedNotClobbered(t *testing.T) {
	srv := flakySqliTarget()
	defer srv.Close()

	// Two seed chunks, both declaring sqli on /x. Worker 1: probe with a quote → SQL error → records
	// the finding. Worker 2: probe with a quote → clean (target fired once) → no finding → grounded
	// Clean (it attempted sqli, evidenced by the quote payload).
	script := &scriptLLM{steps: []string{
		// chunk 1 (highest score — seed with enrichment)
		fmt.Sprintf(`{"tool":"send_request","args":{"method":"GET","url":%q,"payload":"'"}}`, srv.URL+"/x?q='"),
		fmt.Sprintf(`{"tool":"record_finding","args":{"route":%q,"class":"sqli","severity":"high","evidence":["t-001"],"rationale":"error-based"}}`, srv.URL+"/x"),
		`{"tool":"finish","args":{"summary":"found sqli"}}`,
		// chunk 2 (same route, lower score)
		fmt.Sprintf(`{"tool":"send_request","args":{"method":"GET","url":%q,"payload":"'"}}`, srv.URL+"/x?q='"),
		`{"tool":"finish","args":{"summary":"nothing this time"}}`,
	}}

	in := FrontierInput{
		Target: srv.URL,
		Seeds: []webagent.SeedFinding{
			{Route: srv.URL + "/x?q=1", Class: "sqli", Severity: "high", Enrichment: "KEV"}, // ranks first
			{Route: srv.URL + "/x?q=1", Class: "sqli", Severity: "high"},                    // ranks second
		},
	}
	res, err := RunSequential(context.Background(), script, srv.URL, in, webagent.Options{MaxIters: 8, MaxRequests: 20})
	if err != nil {
		t.Fatalf("RunSequential: %v", err)
	}
	rid := routeID(srv.URL + "/x")
	v, ok := res.Worldview.Get(rid, "sqli")
	if !ok {
		t.Fatalf("no verdict for sqli on %s; ledger:\n%s", rid, res.Ledger())
	}
	if v.Verdict != Contested {
		t.Errorf("two disagreeing workers must yield Contested, got %q; ledger:\n%s", v.Verdict, res.Ledger())
	}
	if len(v.Evidence) < 2 {
		t.Errorf("Contested must keep BOTH sides' evidence, got %v", v.Evidence)
	}
	if v.Workers != 2 {
		t.Errorf("both workers touched this route×class, want Workers=2 got %d", v.Workers)
	}
	if !strings.Contains(res.Ledger(), "contested") {
		t.Errorf("ledger must surface the contested verdict:\n%s", res.Ledger())
	}
}

// A chunk that ATTEMPTS a class and finds nothing grounds a Clean; one that merely passes through a
// route grounds only Inconclusive — never a fabricated Clean (§10).
func TestClaimsFromChunk_CleanNeedsAnAttempt(t *testing.T) {
	chunk := Chunk{Class: "sqli", Routes: []string{"https://app/x"}}
	// attempted: a quote payload hit /x, no finding → Clean.
	turnsAttempt := []webagent.Turn{{ID: "t-1", URL: "https://app/x?q='", Payload: "'"}}
	c := ClaimsFromChunk(chunk, nil, turnsAttempt)
	if len(c) != 1 || c[0].Verdict != Clean {
		t.Fatalf("an sqli attempt with no finding must be Clean, got %+v", c)
	}
	// touched-only: a benign GET, no class payload → Inconclusive, NOT Clean.
	turnsTouch := []webagent.Turn{{ID: "t-2", URL: "https://app/x?q=hello", Payload: ""}}
	c2 := ClaimsFromChunk(chunk, nil, turnsTouch)
	if len(c2) != 1 || c2[0].Verdict != Inconclusive {
		t.Fatalf("a benign touch must be Inconclusive (not Clean — we did not test sqli), got %+v", c2)
	}
	// never reached: no turns for the route → no verdict at all.
	if c3 := ClaimsFromChunk(chunk, nil, nil); len(c3) != 0 {
		t.Fatalf("a route never reached must yield no verdict, got %+v", c3)
	}
}
