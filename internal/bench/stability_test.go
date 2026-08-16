package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func f(rule, endpoint string, sev types.Severity) types.Finding {
	return types.Finding{RuleID: rule, Endpoint: endpoint, Severity: sev}
}

// The measured case this metric exists for: identical scans of one unchanged target disagreeing.
// Four real api runs returned 1, 1, 11 and 11 findings with partial=false throughout.
func TestScoreStability_FlagsFindingsMissingFromSomeRuns(t *testing.T) {
	stable := f("nuclei::sqli", "https://x/a", types.SeverityHigh)
	flaky := f("schemathesis::contract", "https://x/b", types.SeverityMedium)

	rep := ScoreStability([]*types.Scan{
		{FindingsEnriched: []types.Finding{stable, flaky}, AnchorsFired: []string{"nuclei", "schemathesis"}},
		{FindingsEnriched: []types.Finding{stable}, AnchorsFired: []string{"nuclei"},
			ToolsFailed: []types.ToolFailure{{Tool: "schemathesis", Reason: "context deadline exceeded"}}},
	})

	if rep.Distinct != 2 || rep.Stable != 1 {
		t.Fatalf("want 2 distinct / 1 stable, got %d/%d", rep.Distinct, rep.Stable)
	}
	if rep.StabilityRate != 0.5 {
		t.Errorf("stability rate = %.2f, want 0.50 — half the findings vanished between runs",
			rep.StabilityRate)
	}
	if len(rep.Flaky) != 1 || rep.Flaky[0].SeenInRuns != 1 {
		t.Errorf("the finding present in only one run must be listed as flaky: %+v", rep.Flaky)
	}
	if !rep.ToolsetVaried {
		t.Error("the runs dispatched different toolsets — that is the cause and must be surfaced")
	}
	if len(rep.FailedTools) != 1 || rep.FailedTools[0] != "schemathesis" {
		t.Errorf("a tool that failed in any run must be named: %v", rep.FailedTools)
	}
}

// A finding present in every run is still unreliable if its severity moves: escalation is
// severity-gated, so drift across the threshold decides whether an incident opens at all.
func TestScoreStability_DetectsSeverityDrift(t *testing.T) {
	rep := ScoreStability([]*types.Scan{
		{FindingsEnriched: []types.Finding{f("r", "https://x/a", types.SeverityHigh)}},
		{FindingsEnriched: []types.Finding{f("r", "https://x/a", types.SeverityLow)}},
	})
	if rep.Stable != 1 || rep.StabilityRate != 1 {
		t.Errorf("the finding appeared in both runs, so presence is stable: %+v", rep)
	}
	if rep.SeverityInconsistent != 1 {
		t.Errorf("same finding reported high then low must count as severity drift, got %d",
			rep.SeverityInconsistent)
	}
}

// Perfect agreement must read as perfect — the metric must not manufacture flakiness.
func TestScoreStability_IdenticalRunsScoreFull(t *testing.T) {
	one := []types.Finding{f("a", "u1", types.SeverityHigh), f("b", "u2", types.SeverityLow)}
	rep := ScoreStability([]*types.Scan{
		{FindingsEnriched: one, AnchorsFired: []string{"nuclei"}},
		{FindingsEnriched: one, AnchorsFired: []string{"nuclei"}},
		{FindingsEnriched: one, AnchorsFired: []string{"nuclei"}},
	})
	if rep.StabilityRate != 1 || len(rep.Flaky) != 0 {
		t.Errorf("identical runs must score 1.00 with no flaky entries: %+v", rep)
	}
	if rep.ToolsetVaried {
		t.Error("identical toolsets must not be reported as varied")
	}
}

// One run cannot measure agreement. Reporting 1.00 there would be the most dangerous possible
// output: a perfect score for a measurement never taken (§10).
func TestScoreStability_SingleRunIsNotPerfect(t *testing.T) {
	rep := ScoreStability([]*types.Scan{
		{FindingsEnriched: []types.Finding{f("a", "u1", types.SeverityHigh)}},
	})
	if rep.StabilityRate != 0 {
		t.Errorf("a single run must not report a stability rate, got %.2f", rep.StabilityRate)
	}
	if out := RenderStability(rep); !strings.Contains(out, "not measurable") {
		t.Errorf("the report must say it is unmeasurable, got:\n%s", out)
	}
}
