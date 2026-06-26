package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
)

// handleComplianceByAsset returns the per-asset compliance signal — the "is THIS asset compliant?" view
// (competitor parity: Vanta shows per-resource status). Tenant-scoped (§18.2 inv. 2): reads only this
// tenant's assets + findings. Grounded (§10): grc.AssetCompliancePosture attributes a finding to an asset
// only when the asset's Target literally appears in the finding's endpoint, and never reports an asset as
// "compliant" — unattributable assets (repo file:line endpoints) come back honestly as "not assessed at the
// asset level".
func (d Deps) handleComplianceByAsset(w http.ResponseWriter, r *http.Request, tenantID string) {
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
	posture := grc.AssetCompliancePosture(assets, findings)
	attributed := 0
	for _, p := range posture {
		if p.Attributed {
			attributed++
		}
	}
	respond(w, map[string]any{"assets": posture, "total": len(posture), "attributed": attributed}, nil)
}
