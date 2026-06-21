package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// assetView is the API shape for an asset: the stored asset plus its derived data-tier fields
// (the tier itself lives in Meta — datatier.go in pkg/platform — but the UX wants it spelled
// out without parsing Meta). Purely presentational; no engine state is changed (§18.2 inv 1).
type assetView struct {
	platform.Asset
	DataTier      int    `json:"data_tier"`
	DataTierLabel string `json:"data_tier_label"`
}

func viewAsset(a platform.Asset) assetView {
	t := a.DataTier()
	return assetView{Asset: a, DataTier: t, DataTierLabel: platform.DataTierLabel(t)}
}

// handleSetAssetDataTier sets an asset's customer-data-sensitivity tier (1 = customer data,
// 2 = standard, 3 = low). The tier raises/lowers the platform's risk-adjusted ranking of that
// asset's findings (crossdetect.RiskWeight) — the Synthesia "tier repos by data exposure"
// control. Tenant-scoped; ledger-recorded as a governance decision.
func (d Deps) handleSetAssetDataTier(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Tier int `json:"tier"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	if !platform.ValidDataTier(body.Tier) {
		writeJSON(w, http.StatusBadRequest, errBody("tier must be 1 (customer data), 2 (standard), or 3 (low)"))
		return
	}
	assets, err := d.Store.ListAssets(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var found *platform.Asset
	for i := range assets {
		if assets[i].ID == id {
			found = &assets[i]
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, errBody("asset not found"))
		return
	}
	updated := found.WithDataTier(body.Tier)
	if err := d.Store.PutAsset(r.Context(), updated); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("asset data-tier set", "data_tier",
			map[string]any{"tenant_id": tenantID, "asset_id": id, "target": updated.Target, "tier": body.Tier, "label": platform.DataTierLabel(body.Tier)},
			"asset data-tier set")
	}
	writeJSON(w, http.StatusOK, viewAsset(updated))
}
