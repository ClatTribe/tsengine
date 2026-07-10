package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
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
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
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
	if t.LLM != nil {
		cfg.KeyRef = t.LLM.KeyRef // preserve the existing key by default
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
	t.LLM = cfg
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("LLM config updated", "llm_config",
			map[string]any{"tenant_id": tenantID, "provider": cfg.Provider, "model": cfg.Model, "has_key": cfg.HasKey()},
			"tenant LLM configured")
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": cfg.Provider, "model": cfg.Model, "has_key": cfg.HasKey(), "base_url": cfg.BaseURL})
}

// resolveTenantLLMConfig returns the tenant's FULL LLM config (incl. BaseURL for a self-hosted model)
// + the opened key. Usable (ok=true) when it carries a key (cloud) OR a self-hosted endpoint (Ollama
// et al. may legitimately have no key). The key is never logged.
func (d Deps) resolveTenantLLMConfig(ctx context.Context, tenantID string) (platform.LLMConfig, string, bool) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || t.LLM == nil {
		return platform.LLMConfig{}, "", false
	}
	key := ""
	if t.LLM.HasKey() {
		if d.Vault == nil {
			return platform.LLMConfig{}, "", false
		}
		k, oerr := d.Vault.Open(t.LLM.KeyRef)
		if oerr != nil || k == "" {
			return platform.LLMConfig{}, "", false
		}
		key = k
	}
	// A config with neither a key nor a self-hosted endpoint can't drive anything.
	if key == "" && !t.LLM.SelfHosted() {
		return platform.LLMConfig{}, "", false
	}
	return *t.LLM, key, true
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
	// A tenant's OWN model (§18.5 "bring your own brain") costs the operator nothing, so it's
	// allowed on ANY plan, Free included. ClientForURL threads the base URL so a self-hosted endpoint
	// is actually reached (and handles anthropic — the UI default — which ClientFor used to drop).
	if cfg, key, ok := d.resolveTenantLLMConfig(ctx, tenantID); ok {
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
