package webagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/breaker"
)

// TestRequester_AutoHaltsAfterRepeatedEgressBlocks is the end-to-end auto-halt proof: after the egress
// guard has refused several requests (the signal the guard records when a scoped host rebinds toward
// metadata), the agent is halted in-flight and every further Send is refused — until a human resumes.
func TestRequester_AutoHaltsAfterRepeatedEgressBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	host := hostOf(srv.URL)
	r := NewRequester([]string{host}, 40, 0)
	ctx := context.Background()

	// baseline — a normal in-scope request works
	if _, err := r.Send(ctx, "GET", srv.URL, "", nil); err != nil {
		t.Fatalf("baseline request should work: %v", err)
	}
	// simulate what the egress guard does on a blocked rebind (3 within the window → trip)
	for i := 0; i < 3; i++ {
		r.Breaker().Record(breaker.EgressBlocked)
	}
	// now the agent is auto-halted — every further request is refused
	_, err := r.Send(ctx, "GET", srv.URL, "", nil)
	if err == nil || !strings.Contains(err.Error(), "AUTO-HALTED") {
		t.Fatalf("after repeated egress blocks Send must auto-halt, got: %v", err)
	}
	// the halt LATCHES — it doesn't clear on its own
	if _, err := r.Send(ctx, "GET", srv.URL, "", nil); err == nil {
		t.Error("the auto-halt must latch (no silent recovery)")
	}
	// only an explicit human resume clears it
	r.Breaker().Reset()
	if _, err := r.Send(ctx, "GET", srv.URL, "", nil); err != nil {
		t.Errorf("after a human resume the agent should send again: %v", err)
	}
}
