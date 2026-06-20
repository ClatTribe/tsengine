package platformapi

import "testing"

// TestAutonomousPentestEntitled pins the ADR-0008 D5 paywall: ModeDeep is available on Scale /
// Enterprise / a Growth plan stamped with the pentest add-on, and refused otherwise.
func TestAutonomousPentestEntitled(t *testing.T) {
	entitled := []string{"scale", "Scale", " ENTERPRISE ", "growth+pentest", "autonomous-pentest"}
	for _, p := range entitled {
		if !autonomousPentestEntitled(p) {
			t.Errorf("%q should be entitled to autonomous pentest", p)
		}
	}
	notEntitled := []string{"", "free", "growth", "starter", "pro"}
	for _, p := range notEntitled {
		if autonomousPentestEntitled(p) {
			t.Errorf("%q should NOT be entitled (no add-on)", p)
		}
	}
}
