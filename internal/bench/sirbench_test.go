package bench

import "testing"

// TestSIRBench_BuiltinSample validates the SIR-Bench-compatible scoring on the representative
// cases: correctly escalate every real incident (incl. the PoC-verified SSRF) and reject every
// false alarm (incl. the adversarial public-sample key + test-fixture decoys).
func TestSIRBench_BuiltinSample(t *testing.T) {
	r := RunSIRBench(nil, false)
	t.Logf("M1 TP=%.0f%% (%d/%d) FP-rejection=%.0f%% (%d/%d) M2=%.2f novel/case M3=%.2f | missed=%v falseAlerts=%v",
		r.M1TP()*100, r.TPDetected, r.Incidents, r.M1FP()*100, r.FPRejected, r.FalseAlarms, r.M2Novel(), r.ToolAppropriate, r.Missed, r.FalseAlerts)
	if r.M1TP() < 1.0 {
		t.Errorf("must detect every real incident, missed %v", r.Missed)
	}
	if r.M1FP() < 1.0 {
		t.Errorf("must reject every false alarm, false alerts %v", r.FalseAlerts)
	}
	if r.NovelDiscovered < 2 {
		t.Errorf("must discover the cross-surface chains as novel findings, got %d", r.NovelDiscovered)
	}
}
