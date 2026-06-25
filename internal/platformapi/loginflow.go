package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/webauth"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleSetLoginFlow configures authenticated scanning for a web asset (ADR 0010 Phase 3 wiring):
// the owner stores a LoginFlow (form / token / recorded) once, and the scanner replays it +
// validates the session each scan (webauth.Replayer) so it never silently scans logged-out (the
// FN guard). Stored as JSON in Asset.Meta["login_flow"] (no struct/serialization churn). The
// flow is validated before it is accepted. Tenant-scoped; ledger-recorded.
func (d Deps) handleSetLoginFlow(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var flow webauth.LoginFlow
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&flow); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid login flow"))
		return
	}
	if err := flow.Valid(); err != nil {
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
	// A login flow holds credentials (passwords / tokens / auth headers), so it must be sealed
	// before it touches the store — never plaintext at rest (§18.2 inv. 6).
	if d.Vault == nil {
		writeJSON(w, http.StatusBadRequest, errBody("secret vault not configured — cannot securely store login credentials"))
		return
	}
	blob, _ := json.Marshal(flow)
	sealed, serr := d.Vault.Seal(string(blob))
	if serr != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("seal login flow: "+serr.Error()))
		return
	}
	m := make(map[string]string, len(found.Meta)+1)
	for k, v := range found.Meta {
		m[k] = v
	}
	m["login_flow"] = sealed // a sealed ref, not the plaintext flow
	found.Meta = m
	if err := d.Store.PutAsset(r.Context(), *found); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("asset login-flow set", "login_flow",
			map[string]any{"tenant_id": tenantID, "asset_id": id, "target": found.Target, "auth_type": string(flow.Type)},
			"authenticated-scan config set")
	}
	// Echo back the asset (with the configured flag); never echo the token in the flow.
	writeJSON(w, http.StatusOK, map[string]any{"asset_id": id, "auth_type": flow.Type, "configured": true})
}
