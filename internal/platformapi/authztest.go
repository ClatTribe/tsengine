package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleSetAuthzTest configures the BOLA/BFLA authorization test for an API asset (ADR 0010
// Phase 1 wiring): the owner stores the two identities (a victim that owns an object, an attacker
// that's a different lower-privilege principal) + the object-bearing operations to test. The
// engine then replays the victim's request as the attacker and flags only a proven bypass
// (apiauthz.Run, gated behind the active-exploit consent flag). Stored as JSON in
// Asset.Meta["authz_test"]; validated before accepted. Tenant-scoped; ledger-recorded; the
// response never echoes the identities' auth headers.
func (d Deps) handleSetAuthzTest(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var cfg apiauthz.TestConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid authz-test config"))
		return
	}
	if err := cfg.Valid(); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
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
	blob, _ := json.Marshal(cfg)
	m := make(map[string]string, len(found.Meta)+1)
	for k, v := range found.Meta {
		m[k] = v
	}
	m["authz_test"] = string(blob)
	found.Meta = m
	if err := d.Store.PutAsset(r.Context(), *found); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("asset authz-test set", "authz_test",
			map[string]any{"tenant_id": tenantID, "asset_id": id, "target": found.Target, "operations": len(cfg.Operations)},
			"BOLA/BFLA test config set")
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": id, "operations": len(cfg.Operations), "configured": true})
}
