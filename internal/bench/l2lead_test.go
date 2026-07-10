package bench

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/l2"
)

// TestRenderChain_ShowsBridgeAndDistinctCrowns locks the L2-estate render improvement: each
// chain must name its BRIDGE entity (why the surfaces connect) and its OWN crown finding
// (distinct crowns must not collapse to the bucketed asset target). This is what lets the L2
// Lead reason about the cross-surface path without drilling in.
func TestRenderChain_ShowsBridgeAndDistinctCrowns(t *testing.T) {
	fs, _ := correlationEstate()
	lines := benchRenderChains(crossdetect.Correlate(nil, fs))
	joined := strings.Join(lines, "\n")

	// the bridge entities must be visible (the WHY of the chain).
	for _, bridge := range []string{"aws_key AKIA", "email j.chen@acme.com", "arn arn:aws:iam::123456789012:role/web-instance-role"} {
		if !strings.Contains(joined, bridge) {
			t.Errorf("chain render must show the bridging entity %q, got:\n%s", bridge, joined)
		}
	}
	// the three DISTINCT crowns must each appear (the old render collapsed them to one target).
	for _, crown := range []string{"administrator access to customer PII", "Privilege escalation to administrator", "web-instance-role has administrator access"} {
		if !strings.Contains(joined, crown) {
			t.Errorf("chain render must name the distinct crown %q, got:\n%s", crown, joined)
		}
	}
}

// scriptedLeadLLM plays a fixed, valid L2 Lead sequence (emit a grounded cross-surface report,
// advance to report, finish with an attack-path summary) so the harness scoring is validated
// deterministically — no proxy/model needed for CI.
type scriptedLeadLLM struct{ i int }

func (m *scriptedLeadLLM) Model() string      { return "scripted" }
func (m *scriptedLeadLLM) ContextWindow() int { return 200000 }
func (m *scriptedLeadLLM) Generate(_ context.Context, _ string, _ []l2.Message, _ []l2.ToolSchema) (l2.Response, error) {
	m.i++
	call := func(name string, args map[string]any) l2.Response {
		return l2.Response{ToolCalls: []l2.ToolCall{{ID: "c", Name: name, Args: args}}, StopReason: "tool_use", Usage: l2.Usage{InputTokens: 10, OutputTokens: 5}}
	}
	switch m.i {
	case 1:
		return call("create_vulnerability_report", map[string]any{
			"title": "Leaked AWS key grants cloud admin", "severity": "critical",
			"evidence_finding_ids": []any{"code-key", "cloud-admin"},
			"plain_english":        "A hardcoded AWS access key in source reaches a cloud principal with administrator access to customer PII — a code-to-cloud attack path.",
			"kill_chain":           "read repo → recover key → assume admin → customer PII",
		}), nil
	case 2, 3, 4:
		return call("advance_phase", map[string]any{}), nil
	default:
		return call("finish_scan", map[string]any{
			"executive_summary": "The top risk is a cross-surface attack path: a leaked AWS key in source reaches cloud administrator control of customer PII. Prioritize cutting this chain over standalone issues.",
		}), nil
	}
}

// TestL2LeadBench_ScriptedGroundedRun validates the harness end to end with a scripted Lead:
// it must score the run as surfacing the cross-surface path, leading with the crown, and
// inventing nothing.
func TestL2LeadBench_ScriptedGroundedRun(t *testing.T) {
	r := RunL2LeadBench(context.Background(), &scriptedLeadLLM{})
	t.Logf("l2 lead: ran=%v committed=%d surfaced=%v led=%v invented=%v", r.Ran, r.CommittedFindings, r.SurfacedAttackPath, r.LedWithCrown, r.Invented)
	if !r.Ran || r.Err != "" {
		t.Fatalf("run failed: err=%q", r.Err)
	}
	if r.CommittedFindings < 1 {
		t.Error("the Lead must commit at least the grounded cross-surface report")
	}
	if !r.SurfacedAttackPath {
		t.Error("harness must detect the surfaced cross-surface attack path")
	}
	if !r.LedWithCrown {
		t.Error("harness must detect the summary leading with the crown chain")
	}
	if len(r.Invented) != 0 {
		t.Errorf("a grounded run must have zero invented identifiers, got %v", r.Invented)
	}
}
