package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
)

// handleComplianceOSCAL (GET /v1/compliance/oscal) serves the crosswalk's control coverage as a NIST OSCAL
// component-definition — the GRC-tool-/auditor-ingestible standard format. Tenant-independent (it's the engine's
// coverage), served as a downloadable JSON attachment.
func (d Deps) handleComplianceOSCAL(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("compliance posture unavailable"))
		return
	}
	b, err := d.GRC.OSCAL(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="tsengine-compliance-oscal.json"`)
	_, _ = w.Write(b)
}

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
