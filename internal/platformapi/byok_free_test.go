package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// BRING YOUR OWN BRAIN, ON ANY PLAN (§18.5) — pinned in the direction that has nothing else holding it.
//
// The economic invariant has a test and a bill attached to it: TestHTTP_FreeTenantCannotSpendOperatorLLM
// fails loudly if a Free tenant ever reaches the operator's LLM budget. That pressure is real and it
// only points one way — toward tightening the gate. Nothing pushes back.
//
// The opposite direction carries no bill, so it has been holding on care alone. A tenant's OWN key
// costs the operator nothing, so it is honoured on EVERY plan including Free, and that is the entire
// self-serve story: someone signs up, pastes their Anthropic key or points at their own Ollama, and
// gets the AI engineer without a sales call. It survives today only because three separate functions
// each happen to check the tenant config BEFORE the plan — resolveLeadClient, resolveAgentLLMForRole
// and aiReadiness. Any one of them "simplified" to a plan check at the top would take the free tier
// with it, and every test in the suite would still pass.
//
// A test that only asserted the negative would actively reward that mistake. These assert the positive.

// tenantWithOwnModel returns Deps holding one tenant on the given plan with its own self-hosted model.
//
// Self-hosted (a base URL, no key) is the honest fixture: it needs no vault, so the test exercises the
// plan decision rather than the sealing machinery, and it is a real supported configuration — Ollama
// and vLLM legitimately have no API key.
func tenantWithOwnModel(t *testing.T, plan string) (Deps, string) {
	t.Helper()
	st := store.NewMemory()
	const tid = "t-byok"
	if err := st.PutTenant(context.Background(), platform.Tenant{
		ID: tid, Plan: plan,
		LLM: &platform.LLMConfig{Provider: "ollama", Model: "llama3.1", BaseURL: "http://localhost:11434/v1"},
	}); err != nil {
		t.Fatal(err)
	}
	// No LeadClient and no AgentLLM: the operator has no model at all here, so anything these
	// resolvers return can ONLY have come from the tenant's own config. That is what makes a
	// non-nil result mean what the test says it means.
	return Deps{Store: st}, tid
}

// The tool-calling Lead — POST /v1/l2/translate, the AI Security Engineer's front door.
func TestFreeTenantWithOwnModel_DrivesTheLead(t *testing.T) {
	for _, plan := range []string{platform.PlanFree, platform.PlanGrowth} {
		d, tid := tenantWithOwnModel(t, plan)
		if d.resolveLeadClient(context.Background(), tid) == nil {
			t.Errorf("plan %q: a tenant's OWN model was refused — bring-your-own-key is meant to work "+
				"on every plan, since it costs the operator nothing. The self-serve tier just died.", plan)
		}
	}
}

// The agent lane — autofix, cloud investigation, pentest spec generation.
func TestFreeTenantWithOwnModel_DrivesTheAgents(t *testing.T) {
	d, tid := tenantWithOwnModel(t, platform.PlanFree)
	for _, role := range []platform.AgentRole{"", platform.RoleCode, platform.RoleAnalysis} {
		if d.resolveAgentLLMForRole(context.Background(), tid, role) == nil {
			t.Errorf("role %q: a Free tenant's own model was refused for agent work", role)
		}
	}
}

// And the tenant must be TOLD it works, from the same decision the resolvers make.
//
// Readiness that disagrees with the resolver is its own failure: a customer who is told to upgrade
// while the feature would in fact have run for them upgrades for nothing, or more likely leaves.
func TestFreeTenantWithOwnModel_IsReportedReady(t *testing.T) {
	d, tid := tenantWithOwnModel(t, platform.PlanFree)
	ai := d.aiReadiness(context.Background(), tid, true)
	if !ai.Configured {
		t.Fatal("a Free tenant with its own model was reported as having no AI configured")
	}
	if ai.Source != "tenant_key" {
		t.Errorf("source = %q, want %q — the operator has no model here, so any other answer is "+
			"claiming a capability that does not exist", ai.Source, "tenant_key")
	}
}

// THE OTHER HALF, restated at the resolver rather than the endpoint.
//
// Without this, all three tests above pass if someone deletes the plan gate entirely — the free tier
// would work beautifully and quietly bill the operator for every free user. The pair is the invariant;
// either one alone is only half of it.
func TestFreeTenantWithoutOwnModel_GetsNothing(t *testing.T) {
	st := store.NewMemory()
	const tid = "t-nokey"
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: tid, Plan: platform.PlanFree}); err != nil {
		t.Fatal(err)
	}
	// An operator model IS configured here — the only thing standing between the tenant and the
	// operator's budget is the plan gate.
	d := Deps{Store: st, LeadClient: &l2.MockClient{ModelName: "mock"}}
	if d.resolveLeadClient(context.Background(), tid) != nil {
		t.Error("ECONOMIC GATE OPEN: a Free tenant with no model of its own reached the operator's")
	}
}
