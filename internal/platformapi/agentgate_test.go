package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestAgentsAreAPaidFeature pins the revenue rule the pricing page sells: the AI agents are what a
// customer BUYS. A Free tenant must not get them — not even by pasting in its own API key, which was
// previously allowed (§18.5 let a tenant's own model run on any plan because it cost us nothing; that
// is true of COST but made the premium free for anyone with a key).
func TestAgentsAreAPaidFeature(t *testing.T) {
	t.Setenv("TSENGINE_DEV_LLM_ALL_PLANS", "") // ensure the dev override is off
	ctx := context.Background()

	for _, c := range []struct {
		plan      string
		ownKey    bool
		wantAgent bool
		why       string
	}{
		{platform.PlanFree, true, false, "Free + own key must be REFUSED — the agents are the product"},
		{platform.PlanFree, false, false, "Free without a key has no agents either"},
		{platform.PlanGrowth, true, true, "Core + own key is exactly what the pricing page sells"},
		{platform.PlanGrowth, false, false, "Core without a model has nothing to run — we don't fund it"},
	} {
		st := store.NewMemory()
		tn := platform.Tenant{ID: "t1", Plan: c.plan}
		if c.ownKey {
			// a keyless self-hosted endpoint = a configured model needing no vault
			tn.LLM = &platform.LLMConfig{Provider: "ollama", Model: "llama3.1", BaseURL: "http://localhost:11434/v1"}
		}
		_ = st.PutTenant(ctx, tn)
		d := Deps{Store: st, Token: "tok"}
		got := d.resolveAgentLLM(ctx, "t1") != nil
		if got != c.wantAgent {
			t.Errorf("plan=%s ownKey=%v: got agent=%v, want %v — %s", c.plan, c.ownKey, got, c.wantAgent, c.why)
		}
	}
}

// TestAgentsAllowed_IsDistinctFromWhoPays: the two gates mean different things and must not be
// conflated — Core runs the agents (AIAgents) but on the customer's budget (AIEnabled=false).
func TestAgentsAllowed_IsDistinctFromWhoPays(t *testing.T) {
	core := platform.Entitlements(platform.PlanGrowth)
	if !core.AIAgents {
		t.Error("Core must include the AI agents — it is what the page sells")
	}
	if core.AIEnabled {
		t.Error("Core must NOT spend the operator's model budget — that is Enterprise")
	}
	ent := platform.Entitlements(platform.PlanEnterprise)
	if !ent.AIAgents || !ent.AIEnabled {
		t.Error("Enterprise gets the agents AND we fund the model")
	}
	free := platform.Entitlements(platform.PlanFree)
	if free.AIAgents || free.AIEnabled {
		t.Error("Free gets neither")
	}
}
