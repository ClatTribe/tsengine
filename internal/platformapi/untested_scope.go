package platformapi

import (
	"context"
	"strings"

	"github.com/ClatTribe/tsengine/internal/coverage"
	"github.com/ClatTribe/tsengine/internal/store"
)

// untested_scope.go: which of a report's scope targets has nothing ever assessed.
//
// A VAPT report is the artifact that leaves the building — a customer forwards it to an auditor or a
// prospect. It said "Overall risk rating: Clear … every monitored asset is currently clean" for a
// scope target that no tool had ever run against, because zero findings from a scanned target and
// zero findings from an unscanned one are the same zero.
//
// That is the same failure as an ingest reporting "0 issues" over devices it silently skipped, on a
// document with far more weight behind it. The engine already computes what was actually tested
// (internal/coverage exists to answer exactly this), so the report only needed to ask.

// untestedScope returns the scope targets that have never completed a scan, in the order they appear
// in scope.
//
// Grounded (§10): a target counts as tested only when a real asset with that exact target has a
// completed scan behind it. Matching is EXACT — a fuzzy match here would quietly credit one host's
// scan to another and reintroduce the false all-clear by a different route. A scope target with no
// asset record at all is untested by definition: nothing could have scanned what we do not have.
//
// Fails toward SAYING SO: if the underlying reads error, every target is reported untested rather
// than silently treated as clean. An over-cautious report is recoverable; a false clean one is what
// this exists to prevent.
func (d Deps) untestedScope(ctx context.Context, tenantID string, scope []string) []string {
	if len(scope) == 0 || d.Store == nil {
		return nil
	}
	all := func() []string {
		out := make([]string, 0, len(scope))
		for _, t := range scope {
			if strings.TrimSpace(t) != "" {
				out = append(out, t)
			}
		}
		return out
	}

	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return all()
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return all()
	}
	engs, err := d.Store.ListEngagements(ctx, tenantID)
	if err != nil {
		return all()
	}

	scanned := make(map[string]bool, len(assets))
	for _, a := range coverage.Compute(assets, findings, engs).Assets {
		if a.Scanned {
			scanned[a.Target] = true
		}
	}

	var out []string
	for _, t := range scope {
		if strings.TrimSpace(t) == "" {
			continue
		}
		if !scanned[t] {
			out = append(out, t)
		}
	}
	return out
}
