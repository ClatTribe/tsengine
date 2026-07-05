package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDiscoverPaths_WallClockBounded: discover_content probes ~48 paths serially, each up to the
// Requester's 15s per-request timeout, so a slow/connection-holding target could otherwise block the
// ReAct agent for minutes (grounded: a live XBEN-103 run hung the agent 7+ min on discover_content).
// discoverBudget must cap the TOTAL wall-clock so the sweep returns with partial results instead of
// hanging. Here each probe sleeps 150ms; unbounded that's ~50*150ms=7.5s, but with a 400ms budget the
// call must return well under the serial time.
func TestDiscoverPaths_WallClockBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := discoverBudget
	discoverBudget = 400 * time.Millisecond
	defer func() { discoverBudget = old }()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 200, 0)
	cc.ctx = context.Background()

	start := time.Now()
	_ = discoverPaths(cc, srv.URL)
	elapsed := time.Since(start)
	// Bounded run returns in ~budget+one-probe; the unbounded serial run would be ~7.5s. A 2s ceiling
	// proves the cap fires while leaving slack for CI jitter.
	if elapsed > 2*time.Second {
		t.Fatalf("discoverPaths not wall-clock bounded: took %v with a %v budget (unbounded would be ~7.5s)", elapsed, discoverBudget)
	}
}

// TestDiscoverParams_WallClockBounded: same cap on the param-discovery path.
func TestDiscoverParams_WallClockBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := discoverBudget
	discoverBudget = 400 * time.Millisecond
	defer func() { discoverBudget = old }()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 200, 0)
	cc.ctx = context.Background()

	start := time.Now()
	_ = discoverParams(cc, srv.URL+"/page")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("discoverParams not wall-clock bounded: took %v with a %v budget", elapsed, discoverBudget)
	}
}
