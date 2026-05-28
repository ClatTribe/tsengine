package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// --- test doubles ------------------------------------------------

type mockTool struct{ name string }

func (m *mockTool) Name() string                                    { return m.name }
func (*mockTool) SandboxExecution() bool                            { return true }
func (*mockTool) MITRETechniques() []string                         { return nil }
func (*mockTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

type mockHandler struct {
	anchors    []tool.Tool
	filterFn   func([]asset.Dispatch) []asset.Dispatch
	normalizes []types.Finding
}

func (*mockHandler) Type() types.AssetType  { return types.AssetWebApplication }
func (h *mockHandler) Anchors() []tool.Tool { return h.anchors }
func (*mockHandler) Registry() []tool.Tool  { return nil }
func (h *mockHandler) PlanAnchors(target types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(target, h.anchors)
}
func (h *mockHandler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	if h.filterFn != nil {
		return h.filterFn(in)
	}
	return in
}
func (h *mockHandler) Normalize([]tool.Result) []types.Finding { return h.normalizes }

type mockDispatcher struct {
	calls       atomic.Int64
	resultsByTool map[string]tool.Result
	errByTool   map[string]error
}

func (m *mockDispatcher) Execute(_ context.Context, name string, _ tool.Args) (tool.Result, error) {
	m.calls.Add(1)
	if err := m.errByTool[name]; err != nil {
		return tool.Result{}, err
	}
	return m.resultsByTool[name], nil
}

// --- tests -------------------------------------------------------

func TestRun_HappyPath(t *testing.T) {
	h := &mockHandler{
		anchors:    []tool.Tool{&mockTool{"nuclei"}, &mockTool{"dalfox"}},
		normalizes: []types.Finding{{ID: "f-0001", Tool: "nuclei"}},
	}
	d := &mockDispatcher{
		resultsByTool: map[string]tool.Result{
			"nuclei": {Findings: []types.SandboxEmittedFinding{{RuleID: "x"}}},
			"dalfox": {Findings: nil},
		},
	}
	findings, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://example.com"},
		h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if d.calls.Load() != 2 {
		t.Errorf("dispatch count: got %d, want 2", d.calls.Load())
	}
	if len(fired) != 2 {
		t.Errorf("fired: %v", fired)
	}
	if len(findings) != 1 {
		t.Errorf("findings: %d", len(findings))
	}
}

func TestRun_FilterShrinksDispatchSet(t *testing.T) {
	h := &mockHandler{
		anchors: []tool.Tool{&mockTool{"nuclei"}, &mockTool{"dalfox"}},
		filterFn: func(in []asset.Dispatch) []asset.Dispatch {
			// Drop all but the first.
			return in[:1]
		},
	}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{}}
	_, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if d.calls.Load() != 1 {
		t.Errorf("filter not honored; dispatched %d times", d.calls.Load())
	}
	if len(fired) != 1 || fired[0] != "nuclei" {
		t.Errorf("fired: %v", fired)
	}
}

func TestRun_OneToolFailsDoesNotAbort(t *testing.T) {
	h := &mockHandler{
		anchors: []tool.Tool{&mockTool{"nuclei"}, &mockTool{"broken"}},
	}
	d := &mockDispatcher{
		resultsByTool: map[string]tool.Result{
			"nuclei": {Findings: []types.SandboxEmittedFinding{{RuleID: "x"}}},
		},
		errByTool: map[string]error{
			"broken": errors.New("kaboom"),
		},
	}
	_, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fired) != 1 || fired[0] != "nuclei" {
		t.Errorf("fired: got %v, want [nuclei] (broken tool excluded)", fired)
	}
}

func TestRun_NilHandlerRejected(t *testing.T) {
	_, _, err := Run(context.Background(), types.Asset{}, nil, &mockDispatcher{})
	if err == nil {
		t.Error("expected error for nil handler")
	}
}

func TestRun_NilDispatcherRejected(t *testing.T) {
	_, _, err := Run(context.Background(), types.Asset{}, &mockHandler{}, nil)
	if err == nil {
		t.Error("expected error for nil dispatcher")
	}
}

func TestConcurrencyLimit_Default(t *testing.T) {
	t.Setenv("TSENGINE_DISPATCH_CONCURRENCY", "")
	if got := concurrencyLimit(); got != 4 {
		t.Errorf("default: got %d, want 4", got)
	}
}

func TestConcurrencyLimit_FromEnv(t *testing.T) {
	t.Setenv("TSENGINE_DISPATCH_CONCURRENCY", "8")
	if got := concurrencyLimit(); got != 8 {
		t.Errorf("got %d, want 8", got)
	}
}

func TestConcurrencyLimit_RejectsBadValue(t *testing.T) {
	t.Setenv("TSENGINE_DISPATCH_CONCURRENCY", "notanumber")
	if got := concurrencyLimit(); got != 4 {
		t.Errorf("fallback: got %d, want 4", got)
	}
}
