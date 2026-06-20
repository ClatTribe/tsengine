package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
)

// handleAttackPaths returns the tenant's cross-surface attack paths — the unified
// cross-detection view. The engine already correlates across assets (a finding on
// one surface that bridges, via a concrete shared identifier, to a crown jewel on
// another: a leaked key in code → cloud admin; an exposed host → an internal
// pivot); this endpoint surfaces it for the dashboard. Grounded: correlate only
// links on a real shared entity, never a guessed connection (§10).
//
// Tenant-scoped (§18.2 inv. 2): it reads only this tenant's assets + findings.
func (d Deps) handleAttackPaths(w http.ResponseWriter, r *http.Request, tenantID string) {
	ctx := r.Context()
	assets, err := d.Store.ListAssets(ctx, tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	findings, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	chains := crossdetect.Correlate(assets, findings)
	if chains == nil {
		chains = []correlate.Chain{} // never null — the frontend maps over this (nil-slice→null guard)
	}
	respond(w, map[string]any{"attack_paths": chains, "count": len(chains)}, nil)
}
