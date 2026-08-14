package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// llmsettings.go is the per-tenant bring-your-own-LLM config (the engine's agent / ModeDeep
// pentest / live bench use it instead of only the LLM_API_KEY env). The API key is sealed by
// the secret Vault before it touches the store and is NEVER returned to the client (§18.2
// inv. 6); GET reports only provider/model + whether a key is set.

var llmProviders = map[string]bool{"anthropic": true, "openai": true, "gemini": true, "ollama": true, "openai-compat": true}

// selfHostedProvider reports whether a provider points at a customer-run OpenAI-compatible endpoint
// (needs a base URL, may have no key) rather than a cloud vendor.
func selfHostedProvider(p string) bool { return p == "ollama" || p == "openai-compat" }

// handleGetLLMSettings returns the tenant's LLM provider/model and whether a key is set —
// never the key itself.
func (d Deps) handleGetLLMSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	hasKey := t.LLM != nil && t.LLM.HasKey()
	// ai_enabled is the single source of truth for "can this tenant run the AI agents": operator-funded
	// (the plan's entitlement) OR the tenant brought its own LLM key (§18.5). The UI reads this to show
	// whether the AI Security Engineer is on, instead of re-deriving plan rules client-side.
	resp := map[string]any{
		"provider":   "",
		"model":      "",
		"has_key":    hasKey,
		"ai_enabled": platform.Entitlements(t.Plan).AIEnabled || hasKey,
	}
	if t.LLM != nil {
		resp["provider"] = t.LLM.Provider
		resp["model"] = t.LLM.Model
		resp["base_url"] = t.LLM.BaseURL // a self-hosted endpoint is not a secret — safe to echo
	}
	// Per-role overrides, so the UI can show which model actually drives each agent lane. Keys are
	// never echoed here either — only whether one is set.
	roles := map[string]any{}
	for _, role := range platform.AgentRoles() {
		if c, ok := t.LLMRoles[role]; ok && c != nil {
			roles[string(role)] = map[string]any{
				"provider": c.Provider, "model": c.Model, "base_url": c.BaseURL, "has_key": c.HasKey(),
			}
		}
	}
	resp["roles"] = roles
	writeJSON(w, http.StatusOK, resp)
}

// handlePutLLMSettings sets the tenant's LLM provider/model and (optionally) seals a new API
// key. An empty api_key keeps the existing sealed key (so you can change the model without
// re-entering the key). The key is sealed via the Vault before persistence.
func (d Deps) handlePutLLMSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		APIKey   string `json:"api_key"`
		BaseURL  string `json:"base_url"`
		// Role optionally scopes this config to ONE kind of agent reasoning (see platform.AgentRole).
		// Empty = the tenant's default model, i.e. the original behaviour. This is what lets a tenant
		// run a self-hosted security model for triage while keeping a frontier model for code.
		Role string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	role := strings.ToLower(strings.TrimSpace(body.Role))
	if role != "" && !platform.ValidAgentRole(role) {
		writeJSON(w, http.StatusBadRequest, errBody("role must be one of: analysis, code (or omitted for the default model)"))
		return
	}
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	if !llmProviders[body.Provider] {
		writeJSON(w, http.StatusBadRequest, errBody("provider must be one of: anthropic, openai, gemini, ollama, openai-compat"))
		return
	}
	if strings.TrimSpace(body.Model) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a model is required"))
		return
	}
	// A self-hosted model (Ollama / vLLM / LM Studio) needs a base URL to reach it (a cloud provider
	// uses its vendor default). The endpoint is the customer's own — stored plain, like Jira.BaseURL.
	baseURL := strings.TrimSpace(body.BaseURL)
	if selfHostedProvider(body.Provider) && baseURL == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a base_url is required for a self-hosted model (e.g. http://localhost:11434/v1)"))
		return
	}
	if !selfHostedProvider(body.Provider) {
		baseURL = "" // cloud providers use their fixed endpoint
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	cfg := &platform.LLMConfig{Provider: body.Provider, Model: strings.TrimSpace(body.Model), BaseURL: baseURL}
	// Preserve the existing key for THIS slot, so the model can be changed without re-entering the key.
	// A role override keeps its own key; only the default slot inherits t.LLM's.
	if role != "" {
		if prev, ok := t.LLMRoles[platform.AgentRole(role)]; ok && prev != nil {
			cfg.KeyRef = prev.KeyRef
		}
	} else if t.LLM != nil {
		cfg.KeyRef = t.LLM.KeyRef
	}
	if k := strings.TrimSpace(body.APIKey); k != "" {
		if d.Vault == nil {
			writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
			return
		}
		ref, serr := d.Vault.Seal(k)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not seal the API key"))
			return
		}
		cfg.KeyRef = ref
	}
	if role != "" {
		if t.LLMRoles == nil {
			t.LLMRoles = map[platform.AgentRole]*platform.LLMConfig{}
		}
		t.LLMRoles[platform.AgentRole(role)] = cfg
	} else {
		t.LLM = cfg
	}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("LLM config updated", "llm_config",
			map[string]any{"tenant_id": tenantID, "provider": cfg.Provider, "model": cfg.Model, "has_key": cfg.HasKey(), "role": role},
			"tenant LLM configured")
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": cfg.Provider, "model": cfg.Model, "has_key": cfg.HasKey(), "base_url": cfg.BaseURL, "role": role})
}

// resolveTenantLLMConfig returns the tenant's FULL LLM config (incl. BaseURL for a self-hosted model)
// + the opened key. Usable (ok=true) when it carries a key (cloud) OR a self-hosted endpoint (Ollama
// et al. may legitimately have no key). The key is never logged.
func (d Deps) resolveTenantLLMConfig(ctx context.Context, tenantID string) (platform.LLMConfig, string, bool) {
	return d.resolveTenantLLMConfigForRole(ctx, tenantID, "")
}

// resolveTenantLLMConfigForRole is the role-aware form. An empty role means "the tenant's default",
// preserving the original single-model behaviour for every existing caller.
//
// Resolution order is per-role override → tenant default → (caller's) operator-global. The override is
// only honoured when it is USABLE, so a partially-filled role config degrades to the tenant default
// rather than disabling the agent — a misconfiguration must never look like "no AI configured".
func (d Deps) resolveTenantLLMConfigForRole(ctx context.Context, tenantID string, role platform.AgentRole) (platform.LLMConfig, string, bool) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return platform.LLMConfig{}, "", false
	}
	cfg := t.LLMForRole(role)
	if cfg == nil {
		return platform.LLMConfig{}, "", false
	}
	key := ""
	if cfg.HasKey() {
		if d.Vault == nil {
			return platform.LLMConfig{}, "", false
		}
		k, oerr := d.Vault.Open(cfg.KeyRef)
		if oerr != nil || k == "" {
			return platform.LLMConfig{}, "", false
		}
		key = k
	}
	// A config with neither a key nor a self-hosted endpoint can't drive anything.
	if key == "" && !cfg.SelfHosted() {
		return platform.LLMConfig{}, "", false
	}
	return *cfg, key, true
}

// ResolveTenantLLM returns the tenant's configured (provider, model, apiKey) for engine agent work.
// ok=false when no usable config exists, so the caller falls back to the env default. The key is
// never logged. A thin wrapper over resolveTenantLLMConfig, kept for its existing callers.
func (d Deps) ResolveTenantLLM(ctx context.Context, tenantID string) (provider, model, apiKey string, ok bool) {
	if cfg, key, o := d.resolveTenantLLMConfig(ctx, tenantID); o {
		return cfg.Provider, cfg.Model, key, true
	}
	return "", "", "", false
}

// resolveAgentLLM returns the LLM that drives an L2 agent for this tenant: the tenant's OWN configured
// model (the §18.5 "bring your own brain" — a cloud key or a SELF-HOSTED Ollama/vLLM endpoint) when
// set + buildable, else the operator-global model (d.AgentLLM). nil when neither is configured.
func (d Deps) resolveAgentLLM(ctx context.Context, tenantID string) pentest.SpecLLM {
	return d.resolveAgentLLMForRole(ctx, tenantID, "")
}

// resolveAgentLLMForRole is the role-aware form: it drives an L2 agent with the model the tenant
// assigned to that KIND of reasoning (platform.AgentRole), falling back to their single default and
// then to the operator-global model.
//
// This exists because the two agent lanes reward different models. Code and exploitation work wants a
// frontier general model; triage/correlation/compliance work is the lane security-specialized models
// are trained for and can be served by a small self-hosted one. Routing per role lets a deployment use
// each where it is actually better, instead of paying frontier prices for triage or accepting an 8B
// model's patch quality. Passing "" keeps the previous single-model behaviour exactly.
func (d Deps) resolveAgentLLMForRole(ctx context.Context, tenantID string, role platform.AgentRole) pentest.SpecLLM {
	// THE CUSTOMER'S OWN CHOICE COMES FIRST — before the tenant key, before the plan. AIMode is an
	// instruction about what may run, not a cost gate, so it also blocks a tenant's own key: someone
	// who chose deterministic-only means it, and is not asking us to spend their money instead of
	// ours. (The kill-switch is folded into ResolveAI, so a frozen tenant lands here too.)
	if !d.aiAllowed(ctx, tenantID).Engineer {
		return nil
	}
	// A tenant's OWN model (§18.5 "bring your own brain") costs the operator nothing, so it's
	// allowed on ANY plan, Free included. ClientForURL threads the base URL so a self-hosted endpoint
	// is actually reached (and handles anthropic — the UI default — which ClientFor used to drop).
	if cfg, key, ok := d.resolveTenantLLMConfigForRole(ctx, tenantID, role); ok {
		if c, ok := cloudengine.ClientForURL(cfg.Provider, cfg.Model, key, cfg.BaseURL); ok {
			return c // cloudengine.LLM satisfies pentest.SpecLLM (same Generate method)
		}
	}
	// The operator-global LLM (d.AgentLLM) spends OUR budget — gate it behind an AI-enabled plan so the
	// Free tier never costs us LLM money (the economic invariant). The DEV-only TSENGINE_DEV_LLM_ALL_PLANS
	// override (operatorLLMAllowed) lets `make dev` + the file-relay proxy power any test tenant.
	if d.operatorLLMAllowed(ctx, tenantID) {
		return d.AgentLLM
	}
	return nil
}

// aiAllowed resolves what the tenant has chosen and is entitled to run. A store error resolves to the
// plan default rather than silently disabling the agents — a transient read failure must not look
// like the customer turned AI off.
func (d Deps) aiAllowed(ctx context.Context, tenantID string) platform.AIPermissions {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return platform.Tenant{}.ResolveAI()
	}
	p := t.ResolveAI()
	// DEV-ONLY override: TSENGINE_DEV_LLM_ALL_PLANS lets a test tenant drive the agents regardless of
	// PLAN (it powers `make dev` + the file-relay proxy). It deliberately does NOT override an
	// explicit deterministic-only choice or the kill-switch: those are INSTRUCTIONS, not entitlements,
	// and a dev flag that quietly ran the agents against a customer's stated "no" would be the wrong
	// kind of convenient.
	if !p.Engineer && t.AIMode == platform.AIModeUnset && !t.AgentsHalted &&
		os.Getenv("TSENGINE_DEV_LLM_ALL_PLANS") == "1" {
		return platform.AIPermissions{Engineer: true, Pentester: true, Mode: platform.AIModeFull,
			Reason: "Dev override (TSENGINE_DEV_LLM_ALL_PLANS) — never set this in production."}
	}
	return p
}
