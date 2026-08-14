package platformapi

import "testing"

// TestAutonomousPentestEntitled pins the ADR-0008 D5 paywall: ModeDeep is available on Scale /
// Enterprise / a recognized base tier stamped with the pentest add-on, and refused otherwise.
func TestAutonomousPentestEntitled(t *testing.T) {
	entitled := []string{"scale", "Scale", " ENTERPRISE ", "growth+pentest", "core+pentest", "free+pentest"}
	for _, p := range entitled {
		if !autonomousPentestEntitled(p) {
			t.Errorf("%q should be entitled to autonomous pentest", p)
		}
	}
	notEntitled := []string{"", "free", "growth", "core", "starter", "pro"}
	for _, p := range notEntitled {
		if autonomousPentestEntitled(p) {
			t.Errorf("%q should NOT be entitled (no add-on)", p)
		}
	}
}

// DELIBERATE BEHAVIOUR CHANGE. This case previously asserted that "autonomous-pentest" IS entitled,
// which was pinning an accident: the add-on was granted by a bare substring test, so any string
// containing "pentest" unlocked the most privileged capability in the product, whatever tier it named.
//
// "autonomous-pentest" names no tier. It appeared in no stored plan and in no code path that sets one
// — only in this assertion and in prose. An add-on now has to ride a tier that actually exists, so a
// string like this resolves to Free with no add-on rather than Free plus exploitation rights.
func TestAddOnCannotRideANonexistentTier(t *testing.T) {
	for _, p := range []string{"autonomous-pentest", "pentest", "groth+pentest", "premium+pentest", "+pentest"} {
		if autonomousPentestEntitled(p) {
			t.Errorf("%q named no real tier but was granted the autonomous-pentest entitlement — an "+
				"unrecognized plan must never hand out the most privileged capability we have", p)
		}
	}
}

// The tier's own public name has to resolve. "Core" is what the pricing page sells and what
// PlanLimits.Label returns, and it was not an accepted alias — so the one word a customer or an
// operator actually reads did not work.
func TestPublicTierNameResolves(t *testing.T) {
	if autonomousPentestEntitled("core") {
		t.Error("core alone should not include the pentest add-on")
	}
	if !autonomousPentestEntitled("core+pentest") {
		t.Error("core+pentest should be entitled — core is the public name for the growth tier")
	}
}
