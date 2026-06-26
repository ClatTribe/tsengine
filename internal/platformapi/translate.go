package platformapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleL2Translate (POST /v1/l2/translate) runs the L2 Lead/translator over the tenant's findings to
// produce the developer/founder-facing CONSULTANT DELIVERABLE — prioritized findings, attack-chain
// narrative, plain-English explanations, remediation. This is the L2 "AI security engineer translates
// for non-security teams" value (§2.2), now reachable from the platform (was CLI/scan-only). The model
// reasons; every recorded report still references the L1 evidence it rests on (§10). Gated on a
// tool-calling LLM (the tenant's own model OR the operator-global one — cloud key or local Ollama); no
// client → 400 with setup guidance, never a fabricated report.
func (d Deps) handleL2Translate(w http.ResponseWriter, r *http.Request, tenantID string) {
	client := d.resolveLeadClient(r.Context(), tenantID)
	if client == nil {
		writeJSON(w, http.StatusBadRequest, errBody("the L2 translator needs a tool-calling LLM: configure one in Settings → LLM, or set ANTHROPIC_API_KEY / LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama, then restart the platform"))
		return
	}
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	if len(findings) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"summary": "No findings to translate yet — run a scan first.", "reports": []types.Finding{}})
		return
	}
	// Translate against the tenant's primary asset (best-effort; synthetic if none).
	target := types.Asset{Type: types.AssetWebApplication, Target: "tenant:" + tenantID}
	if assets, _ := d.Store.ListAssets(r.Context(), tenantID); len(assets) > 0 {
		target = types.Asset{Type: types.AssetType(assets[0].Type), Target: assets[0].Target}
	}
	dep := l2.Deps{Target: target, L1Findings: findings}
	budget := l2.DefaultBudget()
	budget.MaxIterations = 16 // a bounded translate pass (not a full investigation)
	agent, aerr := l2.New(client, l2.BuildCatalog(dep), budget)
	if aerr != nil {
		respond(w, nil, aerr)
		return
	}
	out, rerr := agent.Run(r.Context(), target, findings)
	if rerr != nil {
		respond(w, nil, rerr)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("l2 translated", "l2-lead",
			map[string]any{"tenant_id": tenantID, "reports": len(out.Findings), "iterations": out.Iterations}, "L2 translator deliverable")
	}
	reports := out.Findings
	if reports == nil {
		reports = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": out.Summary, "reports": reports,
		"iterations": out.Iterations, "stop_reason": out.StopReason, "cost_usd": out.CostUSD, "model": out.Model,
	})
}

// resolveLeadClient returns the tool-calling l2.Client for the tenant: its own configured model (the
// OpenAI-compatible family — the per-tenant key opened from the vault) else the operator-global client
// (d.LeadClient, from l2.ClientFromEnv — Anthropic, OpenAI, or a local Ollama). nil when neither is set.
// Anthropic/Gemini per-tenant for the tool-calling seam fall back to the operator-global client (their
// keyed constructors read env), a documented follow-on.
func (d Deps) resolveLeadClient(ctx context.Context, tenantID string) l2.Client {
	if provider, model, key, ok := d.ResolveTenantLLM(ctx, tenantID); ok {
		switch strings.ToLower(provider) {
		case "openai", "openai-compat", "ollama", "vllm", "openrouter", "lmstudio":
			return l2.NewOpenAICompatClient(model, "", key)
		}
	}
	return d.LeadClient
}
