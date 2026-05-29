package orchestrator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
)

func disp(name string) asset.Dispatch {
	return asset.Dispatch{Tool: &mockTool{name}, Args: tool.Args{}}
}

func TestPartitionWaves_AllIndependentOneWave(t *testing.T) {
	in := []asset.Dispatch{disp("nuclei"), disp("dalfox"), disp("httpx")}
	waves := partitionWaves(in)
	if len(waves) != 1 {
		t.Fatalf("independent tools should be one wave; got %d", len(waves))
	}
	if len(waves[0]) != 3 {
		t.Errorf("wave 0 should hold all 3; got %d", len(waves[0]))
	}
}

func TestPartitionWaves_DependentPairOrdered(t *testing.T) {
	// scan_idor depends on scan_auth_flow → auth must be an earlier wave.
	in := []asset.Dispatch{disp("scan_idor"), disp("scan_auth_flow"), disp("nuclei")}
	waves := partitionWaves(in)
	if len(waves) != 2 {
		t.Fatalf("dependent pair → 2 waves; got %d", len(waves))
	}
	// wave 0 holds the writers + independent tools; wave 1 holds scan_idor.
	wave0 := toolSet(waves[0])
	wave1 := toolSet(waves[1])
	if !wave0["scan_auth_flow"] || !wave0["nuclei"] {
		t.Errorf("wave0 should hold writer + independent: %v", wave0)
	}
	if !wave1["scan_idor"] || wave1["scan_auth_flow"] {
		t.Errorf("wave1 should hold only the reader: %v", wave1)
	}
}

func TestPartitionWaves_DependencyAbsentNoExtraWave(t *testing.T) {
	// scan_idor present but its dependency (auth) is NOT in the batch →
	// nothing to wait for → single wave.
	in := []asset.Dispatch{disp("scan_idor"), disp("nuclei")}
	waves := partitionWaves(in)
	if len(waves) != 1 {
		t.Errorf("absent dependency → one wave; got %d", len(waves))
	}
}

func TestPartitionWaves_VerifierAfterDetectors(t *testing.T) {
	in := []asset.Dispatch{disp("verify_finding"), disp("nuclei"), disp("dalfox")}
	waves := partitionWaves(in)
	if len(waves) != 2 {
		t.Fatalf("verifier after detectors → 2 waves; got %d", len(waves))
	}
	if !toolSet(waves[1])["verify_finding"] {
		t.Errorf("verify_finding must be in the last wave")
	}
}

// --- concurrent-fan-out regression (strix Q4.0 anti-bug) -----------

// concurrencyRecorder counts in-flight + max-observed concurrency so we
// can assert the fan-out genuinely parallelises (no per-agent
// cancellation / serializer like strix had pre-Q4.0).
type concurrencyRecorder struct {
	inFlight atomic.Int64
	maxSeen  atomic.Int64
	total    atomic.Int64
}

func (c *concurrencyRecorder) Execute(ctx context.Context, _ string, _ tool.Args) (tool.Result, error) {
	n := c.inFlight.Add(1)
	for {
		m := c.maxSeen.Load()
		if n <= m || c.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond) // hold the slot so overlap is observable
	c.total.Add(1)
	c.inFlight.Add(-1)
	return tool.Result{}, nil
}

func TestExecuteWaves_IndependentRunGenuinelyParallel(t *testing.T) {
	t.Setenv("TSENGINE_DISPATCH_CONCURRENCY", "4")
	rec := &concurrencyRecorder{}
	in := []asset.Dispatch{
		disp("nuclei"), disp("dalfox"), disp("httpx"),
		disp("a"), disp("b"), disp("c"),
	}
	_, fired, err := executeWaves(context.Background(), in, rec)
	if err != nil {
		t.Fatalf("executeWaves: %v", err)
	}
	// All 6 ran — none cancelled (strix's pre-Q4.0 per-agent cancellation).
	if rec.total.Load() != 6 || len(fired) != 6 {
		t.Errorf("expected 6 completions; total=%d fired=%d", rec.total.Load(), len(fired))
	}
	// Genuinely concurrent — max in-flight reached the cap, not 1
	// (strix's serializers pinned fan-out to concurrency=1).
	if rec.maxSeen.Load() < 2 {
		t.Errorf("fan-out not parallel; max concurrency observed = %d (want ≥2)", rec.maxSeen.Load())
	}
	if rec.maxSeen.Load() > 4 {
		t.Errorf("concurrency cap breached: max=%d > 4", rec.maxSeen.Load())
	}
}

func TestExecuteWaves_DependentPairSerializesAcrossWaves(t *testing.T) {
	// A wave boundary means the reader's wave can't overlap the writer's.
	var mu sync.Mutex
	order := []string{}
	d := dispatcherFunc(func(_ context.Context, name string, _ tool.Args) (tool.Result, error) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
		return tool.Result{}, nil
	})
	in := []asset.Dispatch{disp("scan_idor"), disp("scan_auth_flow")}
	if _, _, err := executeWaves(context.Background(), in, d); err != nil {
		t.Fatalf("executeWaves: %v", err)
	}
	// scan_auth_flow (writer, wave 0) must complete before scan_idor
	// (reader, wave 1).
	if len(order) != 2 || order[0] != "scan_auth_flow" || order[1] != "scan_idor" {
		t.Errorf("wave order wrong: %v (want [scan_auth_flow scan_idor])", order)
	}
}

func toolSet(ds []asset.Dispatch) map[string]bool {
	m := map[string]bool{}
	for _, d := range ds {
		m[d.Tool.Name()] = true
	}
	return m
}

// dispatcherFunc adapts a func to the Dispatcher interface.
type dispatcherFunc func(context.Context, string, tool.Args) (tool.Result, error)

func (f dispatcherFunc) Execute(ctx context.Context, name string, args tool.Args) (tool.Result, error) {
	return f(ctx, name, args)
}
