package orchestrator

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// covHandler implements asset.CoverageReporter on top of escHandler's behaviour,
// declaring one gap when the scan produced any finding.
type covHandler struct {
	escHandler
	gaps    int
	sawFind int
}

func (h *covHandler) CoverageGaps(_ types.Asset, findings []types.Finding) []types.Finding {
	h.sawFind = len(findings)
	out := make([]types.Finding, 0, h.gaps)
	for i := 0; i < h.gaps; i++ {
		out = append(out, types.Finding{
			RuleID: "cov::not-checked", Tool: "coverage", Severity: types.SeverityInfo,
			Endpoint: "https://x", Title: "could not check",
		})
	}
	return out
}

// The seam must actually fire, and the gaps must reach the scan's findings. A coverage
// declaration that the orchestrator drops is worse than none: the handler believes it
// disclosed the gap and nothing did.
func TestRun_CoverageGapsAreAppended(t *testing.T) {
	h := &covHandler{escHandler: escHandler{escalate: false}, gaps: 2}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"detector": {Findings: []types.SandboxEmittedFinding{{RuleID: "detector::hit", Tool: "detector"}}},
	}}
	findings, _, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 1 detection + 2 coverage gaps", len(findings))
	}
	var gaps int
	for _, f := range findings {
		if f.RuleID == "cov::not-checked" {
			gaps++
		}
	}
	if gaps != 2 {
		t.Errorf("coverage gaps in output = %d, want 2", gaps)
	}
}

// CoverageGaps is called with the scan's FINAL findings, not the interim detection view,
// so a handler can base its disclosure on everything the scan actually observed.
func TestRun_CoverageGapsSeeTheFinalFindings(t *testing.T) {
	h := &covHandler{escHandler: escHandler{escalate: true}}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"detector":   {Findings: []types.SandboxEmittedFinding{{RuleID: "detector::hit", Tool: "detector"}}},
		"depth_tool": {Findings: []types.SandboxEmittedFinding{{RuleID: "depth_tool::deep", Tool: "depth_tool"}}},
	}}
	if _, _, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.sawFind != 2 {
		t.Errorf("CoverageGaps saw %d findings, want 2 (detection + escalation) — the interim "+
			"view would hide what the depth pass observed", h.sawFind)
	}
}

// A handler that does not implement the interface is unaffected — the same shape as every
// other optional handler seam.
func TestRun_HandlerWithoutCoverageReporterIsUnaffected(t *testing.T) {
	h := &escHandler{escalate: false}
	var _ asset.Handler = h
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"detector": {Findings: []types.SandboxEmittedFinding{{RuleID: "detector::hit", Tool: "detector"}}},
	}}
	findings, _, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("findings = %d, want 1 — no coverage reporter, no extra findings", len(findings))
	}
}
