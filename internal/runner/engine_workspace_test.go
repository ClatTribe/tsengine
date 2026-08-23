package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// engine_workspace_test.go covers the ADR 0029 D2a SEAM: that a scan can learn the host path of the
// tree it is scanning, and that the reachability step runs INSIDE the scan — while the clone still
// exists, since cleanup destroys it on return.
//
// This is the part that has to be tested rather than reasoned about. The analysis itself is covered
// in reachability_test.go; what could silently break here is the wiring — a workspace that never
// reaches the hook, or a hook that runs after teardown and quietly annotates nothing.

// fakeTool is the smallest thing the orchestrator will dispatch.
type fakeTool struct{}

func (fakeTool) Name() string              { return "faketool" }
func (fakeTool) SandboxExecution() bool    { return true }
func (fakeTool) MITRETechniques() []string { return nil }
func (fakeTool) Run(context.Context, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

// fakeHandler always normalises to one dependency finding, so the reachability step has something to
// act on without needing a real scanner.
type fakeHandler struct{}

func (fakeHandler) Type() types.AssetType { return types.AssetRepository }
func (fakeHandler) Anchors() []tool.Tool  { return []tool.Tool{fakeTool{}} }
func (fakeHandler) Registry() []tool.Tool { return nil }
func (fakeHandler) PlanAnchors(t types.Asset) []asset.Dispatch {
	return []asset.Dispatch{{Tool: fakeTool{}, Args: tool.Args{"target": t.Target}}}
}
func (fakeHandler) Filter(_ context.Context, _ types.Asset, d []asset.Dispatch) []asset.Dispatch {
	return d
}
func (fakeHandler) Normalize([]tool.Result) []types.Finding {
	return []types.Finding{{ID: "dep1", Tool: "osv-scanner", RuleID: "osv-scanner::CVE-1",
		Endpoint: "github.com/vendor/vulnpkg", ToolArgs: map[string]string{"ecosystem": "Go"}}}
}

type fakeDispatcher struct{}

func (fakeDispatcher) Execute(context.Context, string, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

func TestScan_RunsReachabilityWithTheScansWorkspace(t *testing.T) {
	var gotRoot string
	var ranBeforeCleanup bool
	cleaned := false

	e := &EngineRunner{
		Resolve: func(types.AssetType) (asset.Handler, error) { return fakeHandler{}, nil },
		NewDispatcherWithWorkspace: func(context.Context, platform.Asset) (orchestrator.Dispatcher, string, func(), error) {
			return fakeDispatcher{}, "/tmp/clone-xyz", func() { cleaned = true }, nil
		},
		Reachability: func(root string, f []types.Finding) []types.Finding {
			gotRoot = root
			ranBeforeCleanup = !cleaned // the clone must still exist when this runs
			return f
		},
	}

	if _, err := e.Scan(context.Background(), platform.Asset{Type: "repository", Target: "https://github.com/acme/app"}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if gotRoot != "/tmp/clone-xyz" {
		t.Errorf("reachability was handed root %q, want the scan's workspace path", gotRoot)
	}
	if !ranBeforeCleanup {
		t.Error("reachability ran AFTER the dispatcher cleanup. The clone is deleted there, so the " +
			"analysis would silently see nothing and annotate nothing — passing tests, empty result.")
	}
	if !cleaned {
		t.Error("the dispatcher cleanup never ran; a scan must not leak its clone")
	}
}

func TestScan_WithoutAWorkspaceFactoryNothingChanges(t *testing.T) {
	// Back-compat, and the honest default. A deployment wired the old way gets no workspace, so the
	// hook must not fire at all rather than firing with an empty root.
	called := false
	e := &EngineRunner{
		Resolve: func(types.AssetType) (asset.Handler, error) { return fakeHandler{}, nil },
		NewDispatcher: func(context.Context, platform.Asset) (orchestrator.Dispatcher, func(), error) {
			return fakeDispatcher{}, func() {}, nil
		},
		Reachability: func(root string, f []types.Finding) []types.Finding {
			called = true
			return f
		},
	}
	if _, err := e.Scan(context.Background(), platform.Asset{Type: "repository", Target: "https://github.com/acme/app"}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if called {
		t.Error("reachability ran for a scan with no workspace — with no tree to read it can only " +
			"produce a verdict about nothing")
	}
}

func TestDispatcherFor_PrefersTheWorkspaceAwareFactory(t *testing.T) {
	e := &EngineRunner{
		NewDispatcher: func(context.Context, platform.Asset) (orchestrator.Dispatcher, func(), error) {
			t.Error("the legacy factory was used while a workspace-aware one was wired")
			return fakeDispatcher{}, func() {}, nil
		},
		NewDispatcherWithWorkspace: func(context.Context, platform.Asset) (orchestrator.Dispatcher, string, func(), error) {
			return fakeDispatcher{}, "/ws", func() {}, nil
		},
	}
	_, ws, _, err := e.dispatcherFor(context.Background(), platform.Asset{})
	if err != nil {
		t.Fatal(err)
	}
	if ws != "/ws" {
		t.Errorf("workspace = %q, want /ws", ws)
	}
}
