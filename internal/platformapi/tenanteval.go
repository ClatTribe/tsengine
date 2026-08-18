package platformapi

import (
	"net/http"

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
	out := map[string]any{"cases": res.Cases, "passed": res.Passed, "failures": res.Failures,
		"by_source": res.BySource, "note": res.Note}
	if agree, ok := res.Agreement(); ok {
		out["agreement"] = agree
	}
	respond(w, out, nil)
}
