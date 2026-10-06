package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/tenanteval"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// llmtrial.go: try a candidate model on the customer's own graded cases BEFORE assigning it.
//
// A cheaper model for triage is only safe where something shows it holds up on THIS estate. The trial
// asks the candidate the same graded cases the assigned model was scored on, records the result under
// its own arm (so it can never move the assigned model's trend), and returns the verdict the settings
// PUT later gates on. Owner-only by the /v1/settings/ prefix: it spends model calls on the customer's
// key, so it is something a person decides to do.
//
// The key, when one is supplied, is used for this trial only. It is never stored and never echoed.

// trialClientFor builds the candidate's client. A variable so tests can supply one without a network.
var trialClientFor = func(provider, model, key, baseURL string) (pentest.SpecLLM, bool) {
	c, ok := cloudengine.ClientForURL(provider, model, key, baseURL)
	return c, ok
}

// routeEvidence is the verdict on moving the analysis lane to candidate ("provider/model"), on the
// suite the tenant has now.
func (d Deps) routeEvidence(ctx context.Context, tenantID, candidate string) tenanteval.RouteEvidence {
	cases, err := d.evalCases(ctx, tenantID)
	if err != nil {
		return tenanteval.RouteEvidence{Status: tenanteval.RouteUnmeasured, Reason: "Your graded cases could not be read, so there is no evidence either way."}
	}
	return tenanteval.RouteVerdict(d.evalRuns(ctx, tenantID), candidate, tenanteval.SuiteHash(cases))
}

func (d Deps) handleLLMTrial(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	var body struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		APIKey   string `json:"api_key"`
		BaseURL  string `json:"base_url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	body.Model = strings.TrimSpace(body.Model)
	if !llmProviders[body.Provider] || body.Model == "" {
		writeJSON(w, http.StatusBadRequest, errBody("provider (anthropic, openai, gemini, ollama, openai-compat) and model are required"))
		return
	}
	baseURL := strings.TrimSpace(body.BaseURL)
	if selfHostedProvider(body.Provider) && baseURL == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a base_url is required for a self-hosted model"))
		return
	}
	if !selfHostedProvider(body.Provider) {
		baseURL = ""
	}
	// The customer's instructions still apply to a trial: a halted workspace or an explicit
	// deterministic-only choice means no model is asked anything.
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	if t.AgentsHalted || t.AIMode == platform.AIModeDeterministic {
		writeJSON(w, http.StatusConflict, errBody("AI is switched off for this workspace (halted, or deterministic-only), so no model can be tried"))
		return
	}
	cases, err := d.evalCases(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	name := body.Provider + "/" + body.Model
	if len(cases) < tenanteval.MinRouteCases {
		writeJSON(w, http.StatusOK, map[string]any{
			"ran": false, "cases": len(cases),
			"reason": "Too few graded cases to judge a model on your estate. They accumulate as you reinstate, suppress and confirm fixes.",
			"evidence": tenanteval.RouteEvidence{Status: tenanteval.RouteUnmeasured,
				Reason: "Fewer graded cases than a routing decision needs."},
		})
		return
	}
	client, ok := trialClientFor(body.Provider, body.Model, strings.TrimSpace(body.APIKey), baseURL)
	if !ok {
		writeJSON(w, http.StatusBadRequest, errBody("could not build a client for that model (check the provider, key and base_url)"))
		return
	}
	// Metered like every other call: a trial is spend, and the ceiling must see it.
	llm := d.meter(aiKind(ctx, "model trial", "eval"), client, tenantID)
	res, err := tenanteval.ScoreModel(ctx, cases, llmJudge{llm})
	if err != nil {
		respond(w, nil, err)
		return
	}
	hash := tenanteval.SuiteHash(cases)
	if res.Cases > 0 {
		ts := now()
		_ = d.Store.PutEvalRun(ctx, platform.EvalRun{
			ID: ts.Format(time.RFC3339Nano) + "-candidate", TenantID: tenantID, RanAt: ts,
			Cases: res.Cases, Passed: res.Passed, SuiteHash: hash,
			Arm: tenanteval.ArmCandidate, Model: name,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ran": true, "model": name, "cases": res.Cases, "passed": res.Passed,
		"unanswered": res.Unanswered, "unanswered_reason": res.UnansweredReason,
		"evidence": tenanteval.RouteVerdict(d.evalRuns(ctx, tenantID), name, hash),
	})
}
