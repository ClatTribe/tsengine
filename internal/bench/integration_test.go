package bench

import "testing"

// TestIntegrationCoverage_EveryIntegrationCleanSweep asserts each deterministic integration
// catches every planted issue and flags no decoy — the credential-free coverage bar.
func TestIntegrationCoverage_EveryIntegrationCleanSweep(t *testing.T) {
	rs := RunIntegrationCoverage()
	if len(rs) < 7 {
		t.Fatalf("expected coverage across ≥7 integrations, got %d", len(rs))
	}
	for _, r := range rs {
		t.Logf("%-32s recall=%.0f%% detected=%d/%d findings=%d fp=%v missed=%v",
			r.Integration, r.Recall()*100, r.Detected, r.Planted, r.Findings, r.FalsePos, r.Missed)
		if !r.Pass() {
			t.Errorf("%s: not a clean sweep — missed=%v falsePos=%v", r.Integration, r.Missed, r.FalsePos)
		}
	}
	sum := SummarizeIntegrationCoverage(rs)
	if sum.Passed != sum.Integrations {
		t.Errorf("every integration must clean-sweep: %d/%d passed", sum.Passed, sum.Integrations)
	}
	if sum.OverallRecall < 1.0 {
		t.Errorf("overall recall must be 100%%, got %.0f%%", sum.OverallRecall*100)
	}
	if !sum.FPControlClean {
		t.Errorf("FP-control must be clean, got %d decoys flagged", sum.FalsePositives)
	}
}
