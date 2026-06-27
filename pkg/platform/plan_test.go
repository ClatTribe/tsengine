package platform

import "testing"

func TestNormalizePlan(t *testing.T) {
	cases := map[string]string{
		"": PlanFree, "  ": PlanFree, "free": PlanFree, "garbage": PlanFree,
		"growth": PlanGrowth, "Growth": PlanGrowth, "starter": PlanGrowth, "pro": PlanGrowth,
		"enterprise": PlanEnterprise, "scale": PlanEnterprise, "Custom": PlanEnterprise, "unlimited": PlanEnterprise,
	}
	for in, want := range cases {
		if got := NormalizePlan(in); got != want {
			t.Errorf("NormalizePlan(%q) = %q, want %q", in, got, want)
		}
	}
}

// The economic invariant: Free must NOT be AI-enabled (no operator LLM spend) and must be
// asset-capped; the paid tiers unlock AI.
func TestEntitlements_FreeIsActuallyFree(t *testing.T) {
	free := Entitlements("free")
	if free.AIEnabled {
		t.Error("Free must NOT have operator-funded AI — that's the whole point")
	}
	if free.MaxAssets <= 0 || free.MaxAssets > 5 {
		t.Errorf("Free must have a small hard asset cap, got %d", free.MaxAssets)
	}
	if free.AllFrameworks || free.ContinuousMonitoring {
		t.Error("Free is core-only, on-demand")
	}
	// empty/unknown plan defaults to Free entitlements (fail-safe).
	if Entitlements("").AIEnabled {
		t.Error("unknown plan must default to Free (no AI)")
	}
}

func TestEntitlements_PaidUnlocksAI(t *testing.T) {
	for _, p := range []string{"growth", "enterprise"} {
		if !Entitlements(p).AIEnabled {
			t.Errorf("%s must enable AI", p)
		}
		if !Entitlements(p).AllFrameworks {
			t.Errorf("%s must include all frameworks", p)
		}
	}
	if Entitlements("growth").MaxAssets < 0 {
		t.Error("Growth is capped, not unlimited")
	}
	if Entitlements("enterprise").MaxAssets != -1 {
		t.Error("Enterprise is unlimited assets")
	}
	if Entitlements("growth").AutonomousPentest {
		t.Error("autonomous pentest is Enterprise-only (or an add-on), not base Growth")
	}
	if !Entitlements("enterprise").AutonomousPentest {
		t.Error("Enterprise includes autonomous pentest")
	}
}
