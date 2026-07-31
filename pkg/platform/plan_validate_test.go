package platform

import "testing"

func TestValidatePlan_AcceptsCanonicalAndAliases(t *testing.T) {
	cases := map[string]string{
		"free": PlanFree, "growth": PlanGrowth, "enterprise": PlanEnterprise,
		"pro": PlanGrowth, "team": PlanGrowth, "starter": PlanGrowth,
		"scale": PlanEnterprise, "custom": PlanEnterprise, "unlimited": PlanEnterprise,
		"  GROWTH  ": PlanGrowth, // case/space insensitive, like NormalizePlan
	}
	for in, want := range cases {
		got, err := ValidatePlan(in)
		if err != nil {
			t.Errorf("ValidatePlan(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ValidatePlan(%q)=%q want %q", in, got, want)
		}
	}
}

func TestValidatePlan_AcceptsAddOns(t *testing.T) {
	got, err := ValidatePlan("pro+pentest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "growth+pentest" {
		t.Fatalf("got %q want growth+pentest", got)
	}
	if !Entitlements(got).AutonomousPentest {
		t.Fatal("the pentest add-on should unlock AutonomousPentest")
	}
}

// The whole reason ValidatePlan exists: NormalizePlan is fail-safe-to-Free, which on a WRITE
// would silently DOWNGRADE a customer who just paid because of a typo. Validation must reject.
func TestValidatePlan_RejectsTyposInsteadOfDowngrading(t *testing.T) {
	// NB: keep these far enough from real words that the misspell linter does not "correct"
	// them — they are deliberately invalid input, not typos to be fixed.
	for _, bad := range []string{"groth", "gold", "entrprse", "", "   ", "growth+wat"} {
		if _, err := ValidatePlan(bad); err == nil {
			t.Errorf("ValidatePlan(%q) should error, but it was accepted", bad)
		}
		// Document the trap this guards: NormalizePlan happily turns the typo into Free.
		if bad != "" && NormalizePlan(bad) != PlanFree {
			t.Errorf("precondition changed: NormalizePlan(%q) no longer falls back to Free", bad)
		}
	}
}
