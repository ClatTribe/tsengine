package loadbench

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/server"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// quietLogs silences the server's per-request logging during a benchmark so the
// throughput numbers aren't drowned (and the log I/O doesn't skew ns/op).
func quietLogs(tb testing.TB) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() { log.SetOutput(prev) })
}

type stubSpawner struct{}

func (stubSpawner) Spawn(context.Context, string) (replay.Dispatcher, func(context.Context) error, error) {
	return stubDispatcher{}, func(context.Context) error { return nil }, nil
}

type stubDispatcher struct{}

func (stubDispatcher) Execute(context.Context, string, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

func testServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	h := server.Handler(server.Config{Token: token, RunsDir: t.TempDir(), Version: "bench"}, stubSpawner{})
	return httptest.NewServer(h)
}

// TestLoad_AuthInvariantHoldsUnderConcurrency is the headline: across thousands of
// concurrent requests, the auth gate must never let an unauthenticated /replay
// through nor reject a valid token — ZERO violations. A pure throughput test would
// miss an auth race; this is the security property the benchmark exists to prove.
func TestLoad_AuthInvariantHoldsUnderConcurrency(t *testing.T) {
	srv := testServer(t, "secret-token")
	defer srv.Close()

	res, err := Run(context.Background(), Config{
		BaseURL: srv.URL, Token: "secret-token", Requests: 6000, Concurrency: 48,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Log("\n" + Render(res))

	if res.AuthViolations != 0 {
		t.Fatalf("AUTH INVARIANT BROKEN: %d violations under load", res.AuthViolations)
	}
	if res.AuthProbes == 0 {
		t.Fatal("no auth probes were issued — benchmark misconfigured")
	}
	if res.Errors != 0 {
		t.Errorf("transport errors under load: %d", res.Errors)
	}
	if !res.Pass {
		t.Errorf("benchmark verdict FAIL: %+v", res)
	}
	if res.Throughput <= 0 {
		t.Errorf("throughput not measured: %.2f", res.Throughput)
	}
	// status sanity: healthz → 200, replay_noauth → 401, replay_auth → 404 (missing scan, auth passed)
	if res.Status[200] == 0 || res.Status[401] == 0 || res.Status[404] == 0 {
		t.Errorf("unexpected status mix: %v", res.Status)
	}
	// roughly even split (each of 3 kinds ~ 1/3); allow slack
	total := res.Requests
	for _, code := range []int{200, 401, 404} {
		if got := res.Status[code]; got < total/4 || got > total/2 {
			t.Errorf("status %d count %d is far from ~1/3 of %d", code, got, total)
		}
	}
}

// A WRONG token must be rejected just as reliably under load (no race that
// accidentally accepts).
func TestLoad_WrongTokenAlwaysRejected(t *testing.T) {
	srv := testServer(t, "the-real-token")
	defer srv.Close()

	res, err := Run(context.Background(), Config{
		BaseURL: srv.URL, Token: "WRONG-token", Requests: 3000, Concurrency: 32,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// replay_auth used a wrong token → 401 expected → wantAuth=true means a 401 is a
	// "violation" of the auth-PASS expectation. With a deliberately wrong token, every
	// authed probe is a violation; that's the point: it proves the server never let a
	// wrong token through. So we assert the server returned 401 for ALL /replay.
	if res.Status[404] != 0 {
		t.Fatalf("a WRONG token reached the replay handler (got %d 404s) — auth bypass", res.Status[404])
	}
	if res.Status[401] == 0 {
		t.Fatal("expected 401s from wrong-token probes")
	}
}

// TestLoad_Duration runs in time-bounded mode.
func TestLoad_Duration(t *testing.T) {
	srv := testServer(t, "tok")
	defer srv.Close()
	res, err := Run(context.Background(), Config{
		BaseURL: srv.URL, Token: "tok", Duration: 150 * time.Millisecond, Concurrency: 8,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Requests == 0 || res.AuthViolations != 0 {
		t.Errorf("duration run: requests=%d violations=%d", res.Requests, res.AuthViolations)
	}
}

// --- Go micro-benchmarks (go test -bench) for the hot paths ---

func BenchmarkHealthz(b *testing.B) {
	quietLogs(b)
	srv := server.Handler(server.Config{Token: "t", RunsDir: b.TempDir(), Version: "v"}, stubSpawner{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
	}
}

func BenchmarkReplayUnauthorized(b *testing.B) {
	quietLogs(b)
	srv := server.Handler(server.Config{Token: "supersecret", RunsDir: b.TempDir(), Version: "v"}, stubSpawner{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/replay", nil)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
	}
}
