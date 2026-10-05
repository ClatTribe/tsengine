package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/internal/tool/deepsec"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// deepsec.go is the platform's gate in front of the deepsec registry tool (internal/tool/deepsec).
//
// deepsec is the one tool whose run SPENDS MONEY, potentially hundreds of dollars, so the replay path
// cannot treat it like nuclei with custom flags. Four decisions, each a refusal rather than a default:
//
//  1. THE TENANT'S OWN OPENAI KEY, NEVER OURS. The operator-global model is never used for deepsec; a
//     customer clicking "review this repository" must not be able to spend the operator's budget at that
//     scale. The wrapper runs the Codex agent, so only an OpenAI key works; anything else is refused with
//     a reason that says how to fix it.
//  2. THE CUSTOMER'S AI CHOICE AND CEILING APPLY. aiAllowed is the same gate every agent passes: a tenant
//     who chose deterministic-only, a halted tenant and an exhausted monthly budget all stop here.
//  3. A CAP IS REQUIRED AND IS CLAMPED TO WHAT IS LEFT. With a monthly ceiling set, the run's cap is
//     lowered to the remaining budget and the response SAYS it was lowered — a cap silently reduced is a
//     review that stops early for a reason the engineer cannot see.
//  4. EVERY RUN IS METERED, cost known or not, so the monthly ceiling sees the most expensive run a
//     tenant will make. An errored run still records a row (cost unknown, never zero).
//
// And for every tool, not only deepsec: arguments beginning with "_" are internal and are stripped from
// the request, so no caller can supply `_api_key` and have a tool run on a key it chose.

// stripInternalArgs removes caller-supplied internal arguments ("_"-prefixed). Only the platform sets them.
func stripInternalArgs(a tool.Args) tool.Args {
	out := tool.Args{}
	for k, v := range a {
		if strings.HasPrefix(k, "_") {
			continue
		}
		out[k] = v
	}
	return out
}

// deepsecReplayArgs validates a deepsec replay and returns the args to dispatch, or an HTTP status and
// reason. notes are what the response should tell the engineer (a clamped cap).
func (d Deps) deepsecReplayArgs(ctx context.Context, tenantID string, in tool.Args) (tool.Args, []string, int, string) {
	if p := d.aiAllowed(ctx, tenantID); !p.Engineer {
		reason := p.Reason
		if reason == "" {
			reason = "AI agents are not enabled for this workspace"
		}
		return nil, nil, http.StatusForbidden, "deepsec is an AI review and cannot run: " + reason
	}
	cfg, key, ok := d.resolveTenantLLMConfigForRole(ctx, tenantID, platform.RoleCode)
	if !ok || key == "" || strings.ToLower(cfg.Provider) != "openai" || strings.TrimSpace(cfg.BaseURL) != "" {
		return nil, nil, http.StatusBadRequest, "deepsec runs the OpenAI Codex agent on your OWN OpenAI key. Add an " +
			"OpenAI key in Settings → AI (the platform's shared model is never used for deepsec, whose runs " +
			"can cost hundreds of dollars on a large repository)."
	}
	maxCost, ok := parseCost(in["max_cost_usd"])
	if !ok || maxCost <= 0 {
		return nil, nil, http.StatusBadRequest, "max_cost_usd is required for deepsec — a review is never run " +
			"without a spending cap. Start small (e.g. 10) and raise it; files already reviewed are not re-billed."
	}
	if maxCost > deepsec.MaxCostCeiling {
		return nil, nil, http.StatusBadRequest, fmt.Sprintf("max_cost_usd may not exceed %.0f for one run", deepsec.MaxCostCeiling)
	}
	var notes []string
	if t, err := d.Store.GetTenant(ctx, tenantID); err == nil && t.MonthlyAIBudgetUSD > 0 {
		spent, _ := d.monthlyAISpend(ctx, tenantID)
		left := remainingBudget(t.MonthlyAIBudgetUSD, spent)
		if left <= 0 {
			return nil, nil, http.StatusForbidden, "this month's AI budget is used up"
		}
		if maxCost > left {
			notes = append(notes, fmt.Sprintf("Your cap of $%.2f was lowered to $%.2f — what is left of this "+
				"month's $%.2f AI budget. The review stops there and says how much it did not cover.",
				maxCost, left, t.MonthlyAIBudgetUSD))
			maxCost = left
		}
	}
	out := stripInternalArgs(in)
	out["max_cost_usd"] = maxCost
	if m, _ := out["model"].(string); strings.TrimSpace(m) == "" && cfg.Model != "" {
		out["model"] = cfg.Model
	}
	out["_api_key"] = key
	return out, notes, 0, ""
}

func parseCost(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}

// recordDeepsecSpend meters a deepsec run from the tool's run summary. The summary crosses the sandbox
// boundary as JSON, so it arrives as a generic map; re-decoding it is how it becomes typed again.
// No summary (the run errored before producing one) still records the run, with its cost UNKNOWN.
func (d Deps) recordDeepsecSpend(ctx context.Context, tenantID string, output any) {
	var o deepsec.Output
	if output != nil {
		if b, err := json.Marshal(output); err == nil {
			_ = json.Unmarshal(b, &o)
		}
	}
	d.recordAISpend(ctx, tenantID, "deepsec", "code", o.CostUSD, o.CostKnown, o.Model, 0)
}
