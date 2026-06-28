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

// Positioning: AI is the PREMIUM. The two AI teammates (operator-funded) live ONLY on Enterprise
// ("talk to us"); the Substrate tier (plan key "growth") is the full deterministic L1.7 substrate
// WITHOUT operator AI. Both paid tiers still include all frameworks + continuous monitoring.
func TestEntitlements_AIIsEnterpriseOnly(t *testing.T) {
	// Substrate ("growth"): full substrate, NO operator AI.
	sub := Entitlements("growth")
	if sub.AIEnabled {
		t.Error("Substrate (growth) must NOT have operator-funded AI — AI is the Enterprise/talk-to-us premium")
	}
	if !sub.AllFrameworks || !sub.ContinuousMonitoring {
		t.Error("Substrate is the FULL deterministic substrate — all frameworks + continuous monitoring")
	}
	if sub.MaxAssets < 0 {
		t.Error("Substrate is asset-capped, not unlimited")
	}
	if sub.AutonomousPentest {
		t.Error("autonomous pentest is Enterprise-only (or an add-on), not base Substrate")
	}
	// Enterprise: BOTH AI teammates + unlimited.
	ent := Entitlements("enterprise")
	if !ent.AIEnabled {
		t.Error("Enterprise must enable the AI Security Engineer")
	}
	if !ent.AutonomousPentest {
		t.Error("Enterprise must include the AI Pentester (autonomous pentest)")
	}
	if !ent.AllFrameworks {
		t.Error("Enterprise must include all frameworks")
	}
	if ent.MaxAssets != -1 {
		t.Error("Enterprise is unlimited assets")
	}
	// The à-la-carte escape hatch: the autonomous-pentest ADD-ON still unlocks AutonomousPentest on
	// the Substrate base tier without buying Enterprise (no string-match drift — §Entitlements).
	if !Entitlements("growth+pentest").AutonomousPentest {
		t.Error("the pentest add-on must unlock AutonomousPentest on the Substrate base tier")
	}
}
