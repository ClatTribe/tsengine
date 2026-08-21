package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// failingDispatcher fails one named tool and succeeds for everything else.
type failingDispatcher struct{ failTool string }

func (d failingDispatcher) Execute(_ context.Context, name string, _ tool.Args) (tool.Result, error) {
	if name == d.failTool {
		return tool.Result{}, errors.New("context deadline exceeded")
	}
	return tool.Result{}, nil
}

// TestExecuteAll_RecordsFailuresForTheArtifact pins the distinction between a tool that ran and found
// nothing and a tool that never ran.
//
// Failures went to stderr only, so vulnerabilities.json could not tell the two apart. Measured cost:
// four runs of the same command against the same unchanged API returned 1, 1, 11 and 11 findings with
// three different toolsets and partial=false every time — a 91% recall collapse that looked, in the
// artifact, exactly like a clean scan.
func TestExecuteAll_RecordsFailuresForTheArtifact(t *testing.T) {
	sink := &failureSink{}
	ctx := withFailureSink(context.Background(), sink)

	dispatches := []asset.Dispatch{
		{Tool: stubTool{name: "nuclei"}},
		{Tool: stubTool{name: "schemathesis"}},
	}
	_, fired, _ := executeAll(ctx, dispatches, failingDispatcher{failTool: "schemathesis"})

	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 recorded failure, got %d (%+v).\n"+
			"Without this the artifact cannot distinguish a timed-out tool from a clean one.", len(got), got)
	}
	if got[0].Tool != "schemathesis" || got[0].Reason == "" {
		t.Errorf("failure must name the tool and carry a reason, got %+v", got[0])
	}
	for _, f := range fired {
		if f == "schemathesis" {
			t.Error("a failed tool must not appear in anchors_fired — that is what made the loss invisible")
		}
	}
}

// A nil sink is the un-instrumented path (internal Run, tests). It must silently discard rather than
// panic, so opting out costs nothing.
func TestFailureSink_NilIsSafe(t *testing.T) {
	var s *failureSink
	s.add("nuclei", "boom")
	if got := s.snapshot(); got != nil {
		t.Errorf("nil sink must yield no failures, got %+v", got)
	}
	if failureSinkFrom(context.Background()) != nil {
		t.Error("a context with no sink attached must return nil")
	}
}

type stubTool struct{ name string }

func (s stubTool) Name() string            { return s.name }
func (stubTool) SandboxExecution() bool    { return true }
func (stubTool) MITRETechniques() []string { return nil }
func (stubTool) Run(context.Context, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

var _ types.ToolFailure // keep the artifact type in view for readers of this test

// The last hop of the chain, at the public boundary the CLI actually calls.
//
// executeAll records a failure into the sink (above) and cmd/tsengine copies the returned
// slice into Scan.ToolsFailed. Between them sits RunWithSurface, which owns the sink and
// must hand it back. If it did not, every layer would be individually correct and the
// artifact would still report tools_failed=0 — which is precisely the state an ip-asset
// scan was in while naabu was stubbed out and never ran.
//
// The chain this completes: a wrapper classifies a non-run via tool.DidNotRun and returns an
// error → executeAll records it and keeps it out of anchors_fired → RunWithSurface returns it
// here → the scorer withholds the verdict it could have faked (bench.withholdIfIncomplete).
// Every hop is now covered by an executing test.
func TestRunWithSurface_ReturnsToolFailuresForTheScanArtifact(t *testing.T) {
	h := &mockHandler{anchors: []tool.Tool{stubTool{name: "naabu"}, stubTool{name: "nmap"}}}
	target := types.Asset{Type: types.AssetWebApplication, Target: "http://example.test"}

	_, fired, _, failures, err := RunWithSurface(context.Background(), target, h, failingDispatcher{failTool: "naabu"})
	if err != nil {
		t.Fatalf("a single tool failing must not fail the whole scan: %v", err)
	}
	if len(failures) != 1 || failures[0].Tool != "naabu" {
		t.Fatalf("RunWithSurface must return the failure so it reaches Scan.ToolsFailed, got %+v.\n"+
			"Without it the artifact reports tools_failed=0 for a tool that never ran, and a "+
			"benchmark scores that silence as a clean result.", failures)
	}
	if failures[0].Reason == "" {
		t.Error("a failure with no reason cannot be acted on")
	}
	for _, f := range fired {
		if f == "naabu" {
			t.Error("a tool that failed must not be listed as fired")
		}
	}
}
