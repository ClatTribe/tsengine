package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
)

// handleSecurityByAsset returns the per-asset security posture — the "is THIS asset secure?" view a
// daily-driver user needs. Tenant-scoped (§18.2 inv. 2): reads only this tenant's assets + findings +
// engagements. Grounded + FP-aware (§10): crossdetect.AssetSecurityPosture attributes a finding to an
// asset only when the asset's Target appears in the finding endpoint, separates confirmed
// (verified/corroborated) from unconfirmed (pattern_match) so a wall of low-confidence noise never reads
// as urgent, and never claims a bare "secure" — a scanned-clean asset is "no issues found in the last
// scan", an un-scanned one says so.
func (d Deps) handleSecurityByAsset(w http.ResponseWriter, r *http.Request, tenantID string) {
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
	// scan-coverage: an asset is "scanned" once it has at least one completed engagement.
	scanned := map[string]bool{}
	if engs, err := d.Store.ListEngagements(ctx, tenantID); err == nil {
		for _, e := range engs {
			if !e.CompletedAt.IsZero() {
				scanned[e.AssetID] = true
			}
		}
	}
	posture := crossdetect.AssetSecurityPosture(assets, findings, scanned)
	atRisk := 0
	for _, p := range posture {
		if p.Confirmed > 0 && (p.Critical+p.High) > 0 {
			atRisk++
		}
	}
	respond(w, map[string]any{"assets": posture, "total": len(posture), "at_risk": atRisk}, nil)
}
