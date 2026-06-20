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

// handleIssues returns the tenant's findings de-duplicated into unified issues —
// the "one issue, many signals" view: the same CVE flagged by trivy, grype, and
// govulncheck is ONE confirmed issue, not three rows of noise. Grounded: an
// issue claims only the scanners that actually reported it. Tenant-scoped.
func (d Deps) handleIssues(w http.ResponseWriter, r *http.Request, tenantID string) {
	findings, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	if err != nil {
		respond(w, nil, err)
		return
	}
	issues := crossdetect.UnifiedIssues(findings)
	if issues == nil {
		issues = []crossdetect.Issue{}
	}
	confirmed := 0
	for _, i := range issues {
		if i.Confirmed {
			confirmed++
		}
	}
	respond(w, map[string]any{"issues": issues, "count": len(issues), "raw_findings": len(findings), "confirmed": confirmed}, nil)
}
