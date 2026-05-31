package cloudquery

import "testing"

// TestTier1_CloudGoatCalibration asserts the engineer reaches the DOCUMENTED
// compromise of each transcribed CloudGoat scenario. The ground truth is the
// scenarios' published pentest solutions (Rhino Security Labs) — not cloudiam —
// so this calibrates the engine + cloudiam against a real-lab reference.
func TestTier1_CloudGoatCalibration(t *testing.T) {
	scenarios := Tier1Scenarios()
	if len(scenarios) == 0 {
		t.Fatal("no Tier-1 scenarios")
	}
	for _, sc := range scenarios {
		r, _ := RunTier1(sc, 40)
		if !r.Pass {
			t.Errorf("[%s] engine missed the documented compromise %v (reached %v) — %s",
				sc.Name, r.Missed, r.Found, sc.Source)
		}
	}
}

// TestTier1_LiveModeGuards confirms live mode refuses to pretend: with no AWS
// creds / cloudgoat / cloudquery present (the CI environment), it returns a clear
// error rather than a false result.
func TestTier1_LiveModeGuards(t *testing.T) {
	if _, err := RunTier1Live(Tier1Scenarios()[0]); err == nil {
		t.Error("live mode must error when its prerequisites are absent, not return a fake result")
	}
}
