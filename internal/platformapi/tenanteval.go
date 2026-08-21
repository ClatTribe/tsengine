package platformapi

import (
	"context"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"net/http"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tenanteval"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleTenantEval scores the current configuration against the tenant's OWN graded cases — the
// evals a customer generates themselves, from decisions they already made, rather than a vendor
// number about a vendor corpus.
func (d Deps) handleTenantEval(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	cases, err := d.evalCases(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	res := tenanteval.Score(cases)
	hash := tenanteval.SuiteHash(cases)

	// Read the history BEFORE recording this run, so the trend compares this run against the
	// previous one rather than against itself.
	// Only this arm's history. Interleaving the two would compare the filter's score against a
	// model's and call the difference a change over time.
	prior := tenanteval.RunsForArm(d.evalRuns(ctx, tenantID), tenanteval.ArmSubstrate)
	trend := tenanteval.TrendOf(append(prior, tenanteval.Run{
		RanAt: now().Format(time.RFC3339Nano), Cases: res.Cases, Passed: res.Passed,
		SuiteHash: hash, BySource: res.BySource,
	}))

	// Record it. Only when there are graded cases: an empty suite has no score, so persisting it
	// would put meaningless points on a timeline (§10).
	if res.Cases > 0 {
		bySource := map[string]int{}
		for k, v := range res.BySource {
			bySource[string(k)] = v
		}
		ts := now()
		_ = d.Store.PutEvalRun(ctx, platform.EvalRun{
			ID: ts.Format(time.RFC3339Nano), TenantID: tenantID, RanAt: ts,
			Cases: res.Cases, Passed: res.Passed, SuiteHash: hash, BySource: bySource,
			Arm: tenanteval.ArmSubstrate,
		})
	}

	out := map[string]any{"cases": res.Cases, "passed": res.Passed, "failures": res.Failures,
		"by_source": res.BySource, "note": res.Note, "suite_hash": hash, "trend": trend}
	if agree, ok := res.Agreement(); ok {
		out["agreement"] = agree
	}
	respond(w, out, nil)
}

// evalRuns returns the tenant's recorded runs OLDEST-FIRST. Sorted here rather than trusting the
// store's ordering: TrendOf compares the last two, so getting the order wrong would silently compare
// the wrong pair, and the four store implementations order by different columns.
func (d Deps) evalRuns(ctx context.Context, tenantID string) []tenanteval.Run {
	recs, err := d.Store.ListEvalRuns(ctx, tenantID)
	if err != nil {
		return nil
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].RanAt.Before(recs[j].RanAt) })
	out := make([]tenanteval.Run, 0, len(recs))
	for _, r := range recs {
		by := map[tenanteval.Source]int{}
		for k, v := range r.BySource {
			by[tenanteval.Source(k)] = v
		}
		out = append(out, tenanteval.Run{
			RanAt: r.RanAt.Format(time.RFC3339Nano), Cases: r.Cases, Passed: r.Passed,
			SuiteHash: r.SuiteHash, BySource: by, Arm: r.Arm, Model: r.Model,
		})
	}
	return out
}

// now is the run clock; a var so a test can freeze it.
var now = func() time.Time { return time.Now().UTC() }

// evalCases builds the tenant's graded suite. Shared by the deterministic and the model endpoints
// so the two arms are scored over exactly the same cases — two callers assembling the suite
// separately would drift, and a comparison between arms graded on different sets means nothing.
func (d Deps) evalCases(ctx context.Context, tenantID string) ([]tenanteval.Case, error) {
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	// The dismissed set lives on the engagements, because a dropped finding exists nowhere else.
	var dismissed []types.Finding
	if engs, eerr := d.Store.ListEngagements(ctx, tenantID); eerr == nil {
		for _, e := range engs {
			dismissed = append(dismissed, e.L15Dismissed...)
		}
	}
	ignores, _ := d.Store.ListIgnoreRules(ctx, tenantID)
	actions, _ := d.Store.ListActions(ctx, tenantID)
	// Explicit judgements are best-effort: a store that cannot serve them must not sink
	// the whole suite, since every other source still works.
	feedback, _ := d.Store.ListFeedback(ctx, tenantID)
	return tenanteval.BuildSuiteFrom(tenanteval.Inputs{
		Findings: findings, Dismissed: dismissed, Ignores: ignores,
		Actions: actions, Feedback: feedback,
	}), nil
}
