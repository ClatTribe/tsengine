package orchestrator

import (
	"context"
	"sync"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// recordingDispatcher captures the args each tool was dispatched with so a
// test can assert how the wave classifier threaded a captured session.
type recordingDispatcher struct {
	mu      sync.Mutex
	seenArg map[string]tool.Args
	results map[string]tool.Result
}

func (r *recordingDispatcher) Execute(_ context.Context, name string, args tool.Args) (tool.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seenArg == nil {
		r.seenArg = map[string]tool.Args{}
	}
	// Copy so later in-place mutation of the dispatch args can't change
	// what we recorded.
	cp := tool.Args{}
	for k, v := range args {
		cp[k] = v
	}
	r.seenArg[name] = cp
	return r.results[name], nil
}

// W6 core: seed_auth runs in wave 0, captures a session, and the
// orchestrator threads that session into the dependent detector's
// args["cookie"] in the next wave. nuclei depends on seed_auth (deps.go),
// so the two land in separate waves and threading kicks in.
func TestExecuteWaves_ThreadsCapturedSession(t *testing.T) {
	seed := &mockTool{"seed_auth"}
	nuc := &mockTool{"nuclei"}
	dispatches := []asset.Dispatch{
		{Tool: seed, Args: tool.Args{"login_url": "https://x/login"}},
		{Tool: nuc, Args: tool.Args{"targets": "https://x/a\nhttps://x/b"}},
	}
	d := &recordingDispatcher{
		results: map[string]tool.Result{
			"seed_auth": {CapturedSession: "session=tok-xyz"},
			"nuclei":    {},
		},
	}

	_, fired, err := executeWaves(context.Background(), dispatches, d)
	if err != nil {
		t.Fatalf("executeWaves: %v", err)
	}
	if len(fired) != 2 {
		t.Fatalf("fired = %v, want both tools", fired)
	}
	got := d.seenArg["nuclei"]["cookie"]
	if got != "session=tok-xyz" {
		t.Fatalf("nuclei cookie = %v, want the captured session threaded in", got)
	}
}

// An explicitly-set cookie must NOT be clobbered by a captured session —
// the per-dispatch cookie wins.
func TestExecuteWaves_DoesNotClobberExplicitCookie(t *testing.T) {
	seed := &mockTool{"seed_auth"}
	nuc := &mockTool{"nuclei"}
	dispatches := []asset.Dispatch{
		{Tool: seed, Args: tool.Args{"login_url": "https://x/login"}},
		{Tool: nuc, Args: tool.Args{"targets": "https://x/a", "cookie": "explicit=1"}},
	}
	d := &recordingDispatcher{
		results: map[string]tool.Result{
			"seed_auth": {CapturedSession: "session=tok-xyz"},
			"nuclei":    {},
		},
	}

	if _, _, err := executeWaves(context.Background(), dispatches, d); err != nil {
		t.Fatalf("executeWaves: %v", err)
	}
	if got := d.seenArg["nuclei"]["cookie"]; got != "explicit=1" {
		t.Fatalf("explicit cookie was clobbered: got %v, want explicit=1", got)
	}
}

// When seed_auth captures nothing (auth failed gracefully), the detector
// runs without a cookie rather than crashing or stalling.
func TestExecuteWaves_NoSessionLeavesCookieUnset(t *testing.T) {
	seed := &mockTool{"seed_auth"}
	nuc := &mockTool{"nuclei"}
	dispatches := []asset.Dispatch{
		{Tool: seed, Args: tool.Args{"login_url": "https://x/login"}},
		{Tool: nuc, Args: tool.Args{"targets": "https://x/a"}},
	}
	d := &recordingDispatcher{
		results: map[string]tool.Result{
			"seed_auth": {}, // no CapturedSession
			"nuclei":    {},
		},
	}

	if _, _, err := executeWaves(context.Background(), dispatches, d); err != nil {
		t.Fatalf("executeWaves: %v", err)
	}
	if _, has := d.seenArg["nuclei"]["cookie"]; has {
		t.Fatalf("expected no cookie threaded when auth captured nothing, got %v", d.seenArg["nuclei"]["cookie"])
	}
}

// Sanity: with seed_auth + a dependent detector present, partitionWaves
// must produce two waves (so the captured session is observable before the
// detector runs). This is the wave-ordering proof.
func TestPartitionWaves_AuthOrdersBeforeDetectors(t *testing.T) {
	dispatches := []asset.Dispatch{
		{Tool: &mockTool{"seed_auth"}},
		{Tool: &mockTool{"nuclei"}},
		{Tool: &mockTool{"dalfox"}},
		{Tool: &mockTool{"sqlmap"}},
	}
	waves := partitionWaves(dispatches)
	if len(waves) != 2 {
		t.Fatalf("want 2 waves (auth, then detectors), got %d", len(waves))
	}
	if len(waves[0]) != 1 || waves[0][0].Tool.Name() != "seed_auth" {
		t.Fatalf("wave 0 should be just seed_auth, got %v", names(waves[0]))
	}
	if len(waves[1]) != 3 {
		t.Fatalf("wave 1 should hold the 3 detectors, got %v", names(waves[1]))
	}
}

func names(ds []asset.Dispatch) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Tool.Name()
	}
	return out
}
