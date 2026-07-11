package bench

import "testing"

// TestTriageBench_SOTAMetrics asserts the deterministic triage hits the AI-SOC bar: catch every
// real threat AND reject every noise/decoy (no calibration failures) on the noisy estate.
func TestTriageBench_SOTAMetrics(t *testing.T) {
	r := RunTriageBench()
	t.Logf("TP-detection=%.0f%% (%d/%d) FP-rejection=%.0f%% (%d/%d) precision=%.0f%% decoys-mis-escalated=%d/%d missed=%v misEsc=%v",
		r.TPRate()*100, r.TPDetected, r.Threats, r.FPRejectionRate()*100, r.FPRejected, r.Noise, r.Precision()*100, r.DecoyEscalated, r.Decoys, r.MissedThreats, r.MisEscalated)
	if r.TPRate() < 1.0 {
		t.Errorf("must detect every real threat, missed %v", r.MissedThreats)
	}
	if r.FPRejectionRate() < 1.0 {
		t.Errorf("must reject every non-actionable alert, wrongly escalated %v", r.MisEscalated)
	}
	if r.DecoyEscalated != 0 {
		t.Errorf("must not be fooled by adversarial decoys, escalated %d", r.DecoyEscalated)
	}
}
