package platform

import "testing"

func withKey(t Tenant) Tenant {
	t.LLM = &LLMConfig{Provider: "ollama", Model: "llama3.1", BaseURL: "http://localhost:11434/v1"}
	return t
}

// ── THE CONTROL DOES WHAT IT SAYS ────────────────────────────────────────────────────────────────

// The whole point: a customer can run LESS than their plan allows.
func TestResolveAI_DeterministicChoiceBeatsAGenerousPlan(t *testing.T) {
	tn := Tenant{Plan: PlanEnterprise, AIMode: AIModeDeterministic}
	got := tn.ResolveAI()
	if got.Engineer || got.Pentester {
		t.Errorf("an Enterprise tenant who chose deterministic still ran agents: %+v", got)
	}
	if got.Reason == "" {
		t.Error("no reason given — a disabled surface would read as broken rather than chosen")
	}
}

// AND IT GATES THEIR OWN KEY TOO. The economic gate ignores a tenant's key because that protects OUR
// budget; this gate is the customer's INSTRUCTION, so it must hold even when the spend is theirs.
// Someone who says deterministic-only is not asking us to spend their money instead of ours.
func TestResolveAI_DeterministicChoiceGatesTheirOwnKey(t *testing.T) {
	tn := withKey(Tenant{Plan: PlanFree, AIMode: AIModeDeterministic})
	if got := tn.ResolveAI(); got.Engineer || got.Pentester {
		t.Errorf("a tenant's own key overrode their explicit deterministic-only choice: %+v", got)
	}
}

// Engineer mode runs the engineer and NOT the pentester — the middle rung has to be real, or there
// are only two settings.
func TestResolveAI_EngineerModeExcludesThePentester(t *testing.T) {
	got := Tenant{Plan: PlanEnterprise, AIMode: AIModeEngineer}.ResolveAI()
	if !got.Engineer {
		t.Error("engineer mode did not enable the engineer")
	}
	if got.Pentester {
		t.Error("engineer mode enabled the pentester — the middle rung is not real")
	}
}

func TestResolveAI_FullModeEnablesBoth(t *testing.T) {
	got := Tenant{Plan: PlanEnterprise, AIMode: AIModeFull}.ResolveAI()
	if !got.Engineer || !got.Pentester {
		t.Errorf("full mode did not enable both: %+v", got)
	}
}

// ── PRECEDENCE ───────────────────────────────────────────────────────────────────────────────────

// The kill-switch beats a customer's own choice. It is a safety control, not a preference.
func TestResolveAI_KillSwitchBeatsEverything(t *testing.T) {
	tn := withKey(Tenant{Plan: PlanEnterprise, AIMode: AIModeFull, AgentsHalted: true})
	got := tn.ResolveAI()
	if got.Engineer || got.Pentester {
		t.Errorf("the kill-switch did not stop the agents: %+v", got)
	}
	if got.Mode != AIModeDeterministic {
		t.Errorf("halted tenant resolved to %q", got.Mode)
	}
}

// A customer can never choose MORE than they are entitled to — asking for full on a Free plan with no
// key gets deterministic, with an explanation of how to actually enable it.
func TestResolveAI_CannotChooseBeyondEntitlement(t *testing.T) {
	got := Tenant{Plan: PlanFree, AIMode: AIModeFull}.ResolveAI()
	if got.Engineer || got.Pentester {
		t.Errorf("a Free tenant with no key got agents by asking: %+v", got)
	}
	if got.Reason == "" {
		t.Error("refusing without saying how to fix it leaves the customer stuck")
	}
}

// Bring-your-own-key unlocks the agents on any plan when the customer HAS chosen them — the §18.5
// promise, now expressed through the control rather than around it.
func TestResolveAI_OwnKeyUnlocksOnAnyPlanWhenChosen(t *testing.T) {
	got := withKey(Tenant{Plan: PlanFree, AIMode: AIModeFull}).ResolveAI()
	if !got.Engineer {
		t.Errorf("a Free tenant with their own key and full mode got no engineer: %+v", got)
	}
}

// ── BACK-COMPAT ──────────────────────────────────────────────────────────────────────────────────

// An unset preference resolves to the plan — every existing tenant is unaffected by this feature
// landing. Without this the change would silently disable AI for the whole install base.
func TestResolveAI_UnsetFallsBackToThePlan(t *testing.T) {
	if got := (Tenant{Plan: PlanEnterprise}).ResolveAI(); !got.Engineer {
		t.Errorf("an existing Enterprise tenant lost AI when the control shipped: %+v", got)
	}
	if got := (Tenant{Plan: PlanFree}).ResolveAI(); got.Engineer {
		t.Errorf("an existing Free tenant gained AI: %+v", got)
	}
}

// ── INPUT HANDLING ───────────────────────────────────────────────────────────────────────────────

// A typo must NOT silently resolve to a different tier than the customer picked — that is how a
// control quietly costs money or leaks work they meant to withhold.
func TestValidAIMode_RejectsUnknownAndEmpty(t *testing.T) {
	for _, bad := range []string{"", "  ", "engneer", "yes", "true", "unset"} {
		if ValidAIMode(bad) {
			t.Errorf("%q was accepted as a settable mode", bad)
		}
	}
	for _, good := range []string{"deterministic", "engineer", "full", "FULL", " engineer "} {
		if !ValidAIMode(good) {
			t.Errorf("%q was rejected", good)
		}
	}
}

func TestNormalizeAIMode_UnknownIsUnsetNotAGuess(t *testing.T) {
	if got := NormalizeAIMode("nonsense"); got != AIModeUnset {
		t.Errorf("unknown input normalised to %q instead of falling back to the plan default", got)
	}
	for in, want := range map[string]AIMode{
		"off": AIModeDeterministic, "none": AIModeDeterministic,
		"both": AIModeFull, "all": AIModeFull, "defense": AIModeEngineer,
	} {
		if got := NormalizeAIMode(in); got != want {
			t.Errorf("NormalizeAIMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every resolution explains itself. A surface that is off must be able to say why, or the customer
// reads it as a bug and files a ticket.
func TestResolveAI_AlwaysExplainsItself(t *testing.T) {
	for _, tn := range []Tenant{
		{Plan: PlanFree},
		{Plan: PlanEnterprise},
		{Plan: PlanEnterprise, AIMode: AIModeDeterministic},
		{Plan: PlanFree, AIMode: AIModeFull},
		{Plan: PlanEnterprise, AgentsHalted: true},
		withKey(Tenant{Plan: PlanFree, AIMode: AIModeEngineer}),
	} {
		if got := tn.ResolveAI(); got.Reason == "" {
			t.Errorf("no reason for tenant %+v", tn)
		}
	}
}
