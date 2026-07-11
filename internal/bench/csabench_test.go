package bench

import "testing"

// TestCSABench_RunsBothScenarios asserts the harness executes the real detectors over both CSA
// scenarios and that the restraint decoys are actually present (so accuracy can't be gamed by
// always-escalating). It does NOT hard-code an accuracy — the number is whatever the detectors do.
func TestCSABench_RunsBothScenarios(t *testing.T) {
	results := RunCSABench()
	if len(results) != 2 {
		t.Fatalf("want 2 scenarios, got %d", len(results))
	}
	for _, r := range results {
		if r.Total < 3 {
			t.Errorf("%s: want ≥3 episodes, got %d", r.Key, r.Total)
		}
		var decoys, threats int
		for _, d := range r.Detail {
			if d.Want {
				threats++
			} else {
				decoys++
			}
		}
		if decoys == 0 {
			t.Errorf("%s: no restraint decoys — accuracy would be gameable by always-escalating", r.Key)
		}
		if threats == 0 {
			t.Errorf("%s: no real threats — recall untested", r.Key)
		}
		t.Logf("%s: %.0f%% (%d/%d) — CSA with-AI %d%%, manual %d%%", r.Key, r.Accuracy(), r.Correct, r.Total, r.AIBench, r.Manual)
	}
}

// TestCSABench_DetectorsGrounded spot-checks that the two real detectors fire on the true-threat
// episodes and stay silent on the decoys — the grounding the accuracy number rests on.
func TestCSABench_DetectorsGrounded(t *testing.T) {
	for _, sc := range CSAScenarios() {
		for _, ep := range sc.Episodes {
			got, ev := ep.verdict()
			if got != ep.escalate {
				t.Errorf("%s/%s: want escalate=%v, got %v (%s)", sc.Key, ep.id, ep.escalate, got, ev)
			}
		}
	}
}
