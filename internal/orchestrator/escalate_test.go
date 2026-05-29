package orchestrator

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// escHandler is a mock asset.Handler that also implements
// asset.EscalationPlanner: detection runs "detector"; if any finding came
// back, it escalates to "depth_tool".
type escHandler struct {
	escalate bool
}

func (*escHandler) Type() types.AssetType { return types.AssetWebApplication }
func (*escHandler) Anchors() []tool.Tool  { return []tool.Tool{&mockTool{"detector"}} }
func (*escHandler) Registry() []tool.Tool { return nil }
func (h *escHandler) PlanAnchors(t types.Asset) []asset.Dispatch {
	return asset.DefaultPlanAnchors(t, h.Anchors())
}
func (*escHandler) Filter(_ context.Context, _ types.Asset, in []asset.Dispatch) []asset.Dispatch {
	return in
}

// Normalize lifts each tool.Result's findings into a Finding (enough for
// the escalation trigger to see a non-empty list).
func (*escHandler) Normalize(results []tool.Result) []types.Finding {
	var out []types.Finding
	for _, r := range results {
		for _, f := range r.Findings {
			out = append(out, types.Finding{RuleID: f.RuleID, Tool: f.Tool, Endpoint: f.Endpoint})
		}
	}
	return out
}

func (h *escHandler) PlanEscalation(t types.Asset, _ []string, findings []types.Finding) []asset.Dispatch {
	if !h.escalate || len(findings) == 0 {
		return nil
	}
	return []asset.Dispatch{{
		Tool:          &mockTool{"depth_tool"},
		Args:          tool.Args{"target": "https://x/flagged"},
		EscalatedFrom: "finding→depth_tool",
	}}
}

func TestRun_EscalationFiresOnSignal(t *testing.T) {
	h := &escHandler{escalate: true}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"detector":   {Findings: []types.SandboxEmittedFinding{{RuleID: "detector::hit", Tool: "detector"}}},
		"depth_tool": {Findings: []types.SandboxEmittedFinding{{RuleID: "depth_tool::deep", Tool: "depth_tool"}}},
	}}
	findings, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Both the detector and the escalated depth tool ran.
	got := map[string]bool{}
	for _, f := range fired {
		got[f] = true
	}
	if !got["detector"] || !got["depth_tool"] {
		t.Errorf("fired = %v, want detector + depth_tool", fired)
	}
	// Findings from both stages are merged + normalized.
	if len(findings) != 2 {
		t.Errorf("findings = %d, want 2 (detection + escalation)", len(findings))
	}
}

func TestRun_NoEscalationWhenNoSignal(t *testing.T) {
	// escalate=false → PlanEscalation returns nothing; only detection runs.
	h := &escHandler{escalate: false}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"detector": {Findings: []types.SandboxEmittedFinding{{RuleID: "detector::hit", Tool: "detector"}}},
	}}
	_, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fired) != 1 || fired[0] != "detector" {
		t.Errorf("fired = %v, want only [detector]", fired)
	}
}

func TestCapEscalation(t *testing.T) {
	mk := func(n int) []asset.Dispatch {
		out := make([]asset.Dispatch, n)
		for i := range out {
			out[i] = asset.Dispatch{Tool: &mockTool{"t"}}
		}
		return out
	}
	t.Setenv("TSENGINE_ESCALATION_MAX", "3")
	if got := capEscalation(mk(10)); len(got) != 3 {
		t.Errorf("cap = %d, want 3", len(got))
	}
	t.Setenv("TSENGINE_ESCALATION_MAX", "")
	if got := capEscalation(mk(60)); len(got) != 50 {
		t.Errorf("default cap = %d, want 50", len(got))
	}
}
