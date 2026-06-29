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

var llmProviders = map[string]bool{"anthropic": true, "openai": true, "gemini": true}

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
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	if !llmProviders[body.Provider] {
		writeJSON(w, http.StatusBadRequest, errBody("provider must be one of: anthropic, openai, gemini"))
		return
	}
	if strings.TrimSpace(body.Model) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a model is required"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	cfg := &platform.LLMConfig{Provider: body.Provider, Model: strings.TrimSpace(body.Model)}
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
	writeJSON(w, http.StatusOK, map[string]any{"provider": cfg.Provider, "model": cfg.Model, "has_key": cfg.HasKey()})
}

// ResolveTenantLLM returns the tenant's configured (provider, model, apiKey) for engine agent
// work, opening the sealed key via the Vault. ok=false when no usable config exists, so the
// caller falls back to the LLM_API_KEY / STRIX_LLM env default. The key is never logged.
func (d Deps) ResolveTenantLLM(ctx context.Context, tenantID string) (provider, model, apiKey string, ok bool) {
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil || t.LLM == nil || !t.LLM.HasKey() || d.Vault == nil {
		return "", "", "", false
	}
	key, oerr := d.Vault.Open(t.LLM.KeyRef)
	if oerr != nil || key == "" {
		return "", "", "", false
	}
	return t.LLM.Provider, t.LLM.Model, key, true
}

// resolveAgentLLM returns the LLM that drives an L2 agent for this tenant: the tenant's OWN configured
// model (the §18.5 "bring your own brain" — an MSP/customer key opened from the vault) when set +
// buildable, else the operator-global model (d.AgentLLM, from cloudengine.LLMFromEnv). nil when neither
// is configured. This is what makes the per-tenant LLM config LIVE instead of dormant.
func (d Deps) resolveAgentLLM(ctx context.Context, tenantID string) pentest.SpecLLM {
	// A tenant's OWN key (§18.5 "bring your own brain") costs the operator nothing, so it's
	// allowed on ANY plan, Free included.
	if provider, model, key, ok := d.ResolveTenantLLM(ctx, tenantID); ok {
		if c, ok := cloudengine.ClientFor(provider, model, key); ok {
			return c // cloudengine.LLM satisfies pentest.SpecLLM (same Generate method)
		}
	}
	// The operator-global LLM (d.AgentLLM) spends OUR budget — gate it behind an AI-enabled
	// plan so the Free tier (and any unknown/empty plan) never costs us LLM money. This is the
	// economic invariant that makes "Free is genuinely free for us" real (pkg/platform/plan.go).
	if d.planLimits(ctx, tenantID).AIEnabled {
		return d.AgentLLM
	}
	return nil
}
