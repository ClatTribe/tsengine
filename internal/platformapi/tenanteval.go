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
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
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

	cases := tenanteval.BuildSuite(findings, dismissed, ignores, actions)
	res := tenanteval.Score(cases)
	hash := tenanteval.SuiteHash(cases)

	// Read the history BEFORE recording this run, so the trend compares this run against the
	// previous one rather than against itself.
	prior := d.evalRuns(ctx, tenantID)
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
			SuiteHash: r.SuiteHash, BySource: by,
		})
	}
	return out
}

// now is the run clock; a var so a test can freeze it.
var now = func() time.Time { return time.Now().UTC() }
