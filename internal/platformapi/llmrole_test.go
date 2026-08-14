package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// roleDeps builds Deps over a memory store holding one tenant.
func roleDeps(t *testing.T, tn platform.Tenant) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), tn); err != nil {
		t.Fatalf("put tenant: %v", err)
	}
	return Deps{Store: st, Vault: idSealer{}}
}

// TestLLMForRole_FallsBackToDefault is the backwards-compatibility guard: a tenant with only the
// single LLM config (every tenant today) must resolve that model for BOTH roles. If this breaks,
// role routing silently disabled the agents for every existing customer.
func TestLLMForRole_FallsBackToDefault(t *testing.T) {
	tn := platform.Tenant{ID: "t1", LLM: &platform.LLMConfig{
		Provider: "ollama", Model: "qwen3:8b", BaseURL: "http://localhost:11434/v1",
	}}
	for _, role := range platform.AgentRoles() {
		got := tn.LLMForRole(role)
		if got == nil {
			t.Fatalf("role %s resolved nil — an existing tenant lost its model", role)
		}
		if got.Model != "qwen3:8b" {
			t.Errorf("role %s = %q, want the tenant default qwen3:8b", role, got.Model)
		}
	}
}

// TestLLMForRole_OverrideWins is the actual feature: the analysis lane uses the security model while
// the code lane keeps the frontier model.
func TestLLMForRole_OverrideWins(t *testing.T) {
	tn := platform.Tenant{
		ID:  "t1",
		LLM: &platform.LLMConfig{Provider: "anthropic", Model: "claude-opus-5", KeyRef: "k"},
		LLMRoles: map[platform.AgentRole]*platform.LLMConfig{
			platform.RoleAnalysis: {Provider: "ollama", Model: "foundation-sec-8b", BaseURL: "http://localhost:11434/v1"},
		},
	}
	if got := tn.LLMForRole(platform.RoleAnalysis); got == nil || got.Model != "foundation-sec-8b" {
		t.Errorf("analysis = %v, want the security model override", got)
	}
	if got := tn.LLMForRole(platform.RoleCode); got == nil || got.Model != "claude-opus-5" {
		t.Errorf("code = %v, want the frontier default (no override set)", got)
	}
}

// TestLLMForRole_UnusableOverrideDegrades pins the grounded-fallback rule: a role config carrying
// neither a key nor an endpoint is inert, so it must fall back to the tenant default rather than
// resolve to something unreachable. A misconfiguration must never read as "no AI configured".
func TestLLMForRole_UnusableOverrideDegrades(t *testing.T) {
	tn := platform.Tenant{
		ID:  "t1",
		LLM: &platform.LLMConfig{Provider: "anthropic", Model: "claude-opus-5", KeyRef: "k"},
		LLMRoles: map[platform.AgentRole]*platform.LLMConfig{
			// no KeyRef and no BaseURL — cannot reach anything
			platform.RoleAnalysis: {Provider: "openai", Model: "gpt-4o"},
		},
	}
	got := tn.LLMForRole(platform.RoleAnalysis)
	if got == nil || got.Model != "claude-opus-5" {
		t.Errorf("analysis = %v, want fallback to the usable tenant default", got)
	}
}

// TestLLMForRole_NoConfigIsNil keeps the operator-global fallback reachable: with nothing configured,
// resolution must report nil so the caller drops through to d.AgentLLM.
func TestLLMForRole_NoConfigIsNil(t *testing.T) {
	tn := platform.Tenant{ID: "t1"}
	if got := tn.LLMForRole(platform.RoleAnalysis); got != nil {
		t.Errorf("got %v, want nil so the operator-global model is used", got)
	}
}

// TestResolveAgentLLMForRole_RoutesThroughStore exercises the real resolver end to end (store read,
// vault open, client build) rather than just the pure helper.
func TestResolveAgentLLMForRole_RoutesThroughStore(t *testing.T) {
	d := roleDeps(t, platform.Tenant{
		ID:  "t1",
		LLM: &platform.LLMConfig{Provider: "ollama", Model: "qwen3:8b", BaseURL: "http://localhost:11434/v1"},
		LLMRoles: map[platform.AgentRole]*platform.LLMConfig{
			platform.RoleAnalysis: {Provider: "ollama", Model: "foundation-sec-8b", BaseURL: "http://localhost:11434/v1"},
		},
	})
	ctx := context.Background()

	cfg, _, ok := d.resolveTenantLLMConfigForRole(ctx, "t1", platform.RoleAnalysis)
	if !ok || cfg.Model != "foundation-sec-8b" {
		t.Errorf("analysis resolved %q (ok=%v), want foundation-sec-8b", cfg.Model, ok)
	}
	cfg, _, ok = d.resolveTenantLLMConfigForRole(ctx, "t1", platform.RoleCode)
	if !ok || cfg.Model != "qwen3:8b" {
		t.Errorf("code resolved %q (ok=%v), want the default qwen3:8b", cfg.Model, ok)
	}
	// The role-free form must behave exactly as before.
	cfg, _, ok = d.resolveTenantLLMConfig(ctx, "t1")
	if !ok || cfg.Model != "qwen3:8b" {
		t.Errorf("default resolved %q (ok=%v), want qwen3:8b", cfg.Model, ok)
	}

	if d.resolveAgentLLMForRole(ctx, "t1", platform.RoleAnalysis) == nil {
		t.Error("analysis agent LLM is nil — the client failed to build")
	}
}

// TestRedactedDropsRoleConfigs guards §18.2 inv. 6: role overrides carry sealed key refs, so they must
// never reach a client. Redacted() drops LLM; it has to drop LLMRoles for the same reason.
func TestRedactedDropsRoleConfigs(t *testing.T) {
	tn := platform.Tenant{
		ID:  "t1",
		LLM: &platform.LLMConfig{Provider: "anthropic", Model: "m", KeyRef: "sealed-default"},
		LLMRoles: map[platform.AgentRole]*platform.LLMConfig{
			platform.RoleAnalysis: {Provider: "openai", Model: "m2", KeyRef: "sealed-role"},
		},
	}
	r := tn.Redacted()
	if r.LLM != nil {
		t.Error("Redacted() leaked the default LLM config")
	}
	if r.LLMRoles != nil {
		t.Error("Redacted() leaked LLMRoles — those carry sealed key refs too")
	}
}
