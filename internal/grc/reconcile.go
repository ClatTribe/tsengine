package grc

import (
	"context"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ReconcileResult reports what a compliance-reconciliation pass changed.
type ReconcileResult struct {
	Cleared   int // gaps flipped to Met because the driving finding is gone (remediated)
	Refreshed int // gaps still failing — evidence refreshed to the live finding set
}

// Reconcile folds the CURRENT finding set into the compliance posture and CLEARS gaps whose driving
// findings have been remediated. grc.Apply is upsert-only — it can open a control gap but never close one —
// so without this a fixed issue's gap would persist forever and the framework would read a stale
// "non-compliant" (false NON-compliant, the mirror of the false-compliant failure mode). This mirrors
// detect.Reconcile for incidents: a ControlGap whose evidence findings no longer appear in `current` is
// flipped to ControlMet; one that still appears has its evidence refreshed to the live finding ids.
//
// It only touches ControlGap states — human attestations (ControlAttestation) and ControlException states
// are never clobbered (§18.4 HITL judgment stands). `current` must be the tenant's full current finding
// set (as the runner passes to detect.Reconcile); same scan-vs-ingest caveat applies. Idempotent.
func (g *GRC) Reconcile(ctx context.Context, tenantID string, current []types.Finding) (ReconcileResult, error) {
	// currently-cited controls per framework → the live finding ids that cite them
	cited := map[string]map[string][]string{}
	for _, f := range current {
		if f.Compliance == nil {
			continue
		}
		for fw, ctrls := range frameworkControls(f.Compliance) {
			if cited[fw] == nil {
				cited[fw] = map[string][]string{}
			}
			for _, c := range ctrls {
				cited[fw][c] = append(cited[fw][c], f.ID)
			}
		}
	}

	var res ReconcileResult
	for _, fw := range Frameworks {
		states, err := g.Store.Posture(ctx, tenantID, fw)
		if err != nil {
			return res, err
		}
		for _, cs := range states {
			if cs.State != platform.ControlGap {
				continue // leave Met / Exception / human-attested states untouched
			}
			refs, still := cited[fw][cs.ControlID]
			if still {
				cs.EvidenceRefs = refs
				cs.UpdatedAt = g.now()
				if err := g.Store.UpsertControlState(ctx, cs); err != nil {
					return res, err
				}
				res.Refreshed++
			} else {
				cs.State = platform.ControlMet
				cs.EvidenceRefs = nil
				cs.UpdatedAt = g.now()
				if err := g.Store.UpsertControlState(ctx, cs); err != nil {
					return res, err
				}
				res.Cleared++
			}
		}
	}
	return res, nil
}
