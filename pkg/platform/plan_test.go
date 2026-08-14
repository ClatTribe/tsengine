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
// THE ECONOMIC INVARIANT, which survived the pricing change and is the one that actually matters:
// a tenant on a plan we do not charge for must never spend the operator's LLM budget.
//
// This test used to assert "AI is Enterprise-only". That policy was deliberately changed — the product
// IS the two agents, and putting them behind "talk to us" meant the buyer who decides in a week and
// pays by card could not purchase the thing we sell. What must NOT change is Free's economics, so that
// is what this pins now.
func TestEntitlements_FreeNeverSpendsOperatorBudget(t *testing.T) {
	free := Entitlements("free")
	if free.AIEnabled {
		t.Error("Free must NEVER have operator-funded AI — it is the tier we give away")
	}
	if free.AutonomousPentest {
		t.Error("Free must not include the autonomous pentester")
	}
	if free.MaxAssets < 0 {
		t.Error("Free must be asset-capped")
	}
}

// Core ("growth") is the self-serve tier that includes the AI Security Engineer. This is the change:
// the engineer is purchasable by card, not behind a sales call.
func TestEntitlements_CoreIncludesTheEngineerSelfServe(t *testing.T) {
	core := Entitlements("growth")
	if !core.AIEnabled {
		t.Error("Core must include the AI Security Engineer — AI behind talk-to-us was the blocker")
	}
	if core.AutonomousPentest {
		t.Error("Core must NOT include the pentester; that is the +pentest tier above it")
	}
	if !core.AllFrameworks || !core.ContinuousMonitoring {
		t.Error("Core is the FULL deterministic engine — all frameworks + continuous monitoring")
	}
	if core.MaxAssets < 0 {
		t.Error("Core is asset-capped, not unlimited")
	}
}

// The pentester rides the EXISTING "+pentest" add-on, which is why this restructure needed no new plan
// key and left the "scale"/"custom" aliases (which resolve to Enterprise) untouched.
func TestEntitlements_PentesterRidesTheAddOn(t *testing.T) {
	if !Entitlements("growth+pentest").AutonomousPentest {
		t.Error("the +pentest add-on must unlock the AI Pentester on the Core base tier")
	}
	if !Entitlements("growth+pentest").AIEnabled {
		t.Error("the pentest tier must still include the engineer it builds on")
	}
}

// Enterprise remains talk-to-us for what genuinely needs a conversation — unlimited assets, MSP, SSO —
// and still includes both agents.
func TestEntitlements_EnterpriseIsScaleNotAnAIGate(t *testing.T) {
	ent := Entitlements("enterprise")
	if !ent.AIEnabled || !ent.AutonomousPentest {
		t.Error("Enterprise must include both agents")
	}
	if ent.MaxAssets != -1 {
		t.Error("Enterprise is unlimited assets — that, not AI, is what it gates")
	}
	// The aliases must still resolve, or a stored plan value would silently downgrade a paying customer.
	for _, alias := range []string{"scale", "custom", "unlimited"} {
		if Entitlements(alias).MaxAssets != -1 {
			t.Errorf("alias %q no longer resolves to Enterprise — a stored plan value would downgrade", alias)
		}
	}
}
