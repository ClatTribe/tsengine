package platformapi

import (
	"context"
	"net/http"
	"strings"

	"time"

	"github.com/ClatTribe/tsengine/internal/tenanteval"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// llmJudge adapts the tenant's configured model to the eval's grader interface.
//
// It is a grader and nothing else. Nothing it returns can suppress, keep or alter a real finding —
// the pipeline's verdicts still come from the L1.5 chain. An eval whose subject could change the
// system it is measured on would be worthless twice over.
type llmJudge struct {
	llm interface {
		Generate(ctx context.Context, prompt string) (string, error)
	}
}

func (j llmJudge) Judge(ctx context.Context, f types.Finding) (tenanteval.Verdict, error) {
	out, err := j.llm.Generate(ctx, tenanteval.PromptFor(f))
	if err != nil {
		return "", err
	}
	v, ok := tenanteval.ParseVerdict(out)
	if !ok {
		// An unreadable answer is not an answer. ScoreModel counts it against the model rather than
		// letting a shrug be scored as agreement.
		return "", errUnreadableVerdict
	}
	return v, nil
}

var errUnreadableVerdict = &verdictError{"model did not answer KEEP or SUPPRESS"}

type verdictError struct{ s string }

func (e *verdictError) Error() string { return e.s }

// handleTenantEvalModel (POST /v1/eval/model) scores the tenant's OWN model against their OWN
// graded cases, and reports it beside the deterministic filter's score.
//
// A SEPARATE ENDPOINT, and a POST, on purpose. GET /v1/eval is free: it replays cases through a
// local chain and a page can poll it. This one spends a model call per case and real money on the
// customer's key, so it must be something a person asks for, never something a dashboard does on
// render.
func (d Deps) handleTenantEvalModel(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	cases, err := d.evalCases(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}

	llm := d.resolveAgentLLMForRole(ctx, tenantID, platform.RoleAnalysis)
	if llm == nil {
		// Honest refusal, not a zero. A customer reading a 0 would conclude their model is useless
		// when the truth is we never asked it anything.
		writeJSON(w, http.StatusOK, map[string]any{
			"ran": false,
			"reason": "No model is configured for this workspace, so there is nothing to grade. Add your " +
				"own API key in Settings → LLM and run this again.",
			"cases": len(cases),
		})
		return
	}

	sub := tenanteval.Score(cases)
	mod, merr := tenanteval.ScoreModel(ctx, cases, llmJudge{llm})
	if merr != nil {
		respond(w, nil, merr)
		return
	}
	ab := tenanteval.Compare(sub, mod)
	hash := tenanteval.SuiteHash(cases)

	// The model arm gets its own recorded history, so switching models is VISIBLE rather than
	// something a customer has to remember. Read before writing, so the trend compares this run
	// against the previous one rather than against itself.
	modelName := d.agentModelName(ctx, tenantID)
	prior := tenanteval.RunsForArm(d.evalRuns(ctx, tenantID), tenanteval.ArmModel)
	trend := tenanteval.TrendOf(append(prior, tenanteval.Run{
		RanAt: now().Format(time.RFC3339Nano), Cases: mod.Cases, Passed: mod.Passed,
		SuiteHash: hash, Arm: tenanteval.ArmModel, Model: modelName,
	}))
	// Only with graded cases: an empty suite has no score, so recording it would put meaningless
	// points on a timeline.
	if mod.Cases > 0 {
		ts := now()
		_ = d.Store.PutEvalRun(ctx, platform.EvalRun{
			ID: ts.Format(time.RFC3339Nano), TenantID: tenantID, RanAt: ts,
			Cases: mod.Cases, Passed: mod.Passed, SuiteHash: hash,
			Arm: tenanteval.ArmModel, Model: modelName,
		})
	}

	out := map[string]any{
		"trend": trend, "model_name": modelName,
		"ran": true, "cases": mod.Cases, "suite_hash": hash,
		"substrate": map[string]any{"passed": sub.Passed, "cases": sub.Cases},
		"model": map[string]any{
			"passed": mod.Passed, "unanswered": mod.Unanswered,
			"failures": mod.Failures, "by_source": mod.BySource, "note": mod.Note,
			"unanswered_reason": mod.UnansweredReason,
		},
		"ablation": ab,
	}
	if agree, ok := mod.Agreement(); ok {
		out["model_agreement"] = agree
	}
	if agree, ok := sub.Agreement(); ok {
		out["substrate_agreement"] = agree
	}
	respond(w, out, nil)
}

// agentModelName names the model that graded a run, so a score that moved because the customer
// switched models is distinguishable from one that moved on its own.
//
// A tenant's OWN configured model is named exactly. When the operator-global model did the grading
// there is no per-tenant name to report, and inventing one — or reporting the operator's model as
// if the customer had chosen it — would put a name in their history they never set. So it says what
// it is instead.
func (d Deps) agentModelName(ctx context.Context, tenantID string) string {
	if cfg, _, ok := d.resolveTenantLLMConfigForRole(ctx, tenantID, platform.RoleAnalysis); ok {
		if m := strings.TrimSpace(cfg.Model); m != "" {
			if p := strings.TrimSpace(cfg.Provider); p != "" {
				return p + "/" + m
			}
			return m
		}
	}
	return "platform default"
}
