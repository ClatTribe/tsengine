package platformapi

import (
	"encoding/json"
	"net/http"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleQuarantineConnection is the per-connection kill-switch (agentic-SMB spec WRD-4):
// quarantine ONE connection — the agent stops scanning and acting through it — without
// halting the rest of the roster (that's the global kill-switch, OM-3). A quarantined
// connection is non-active, so the runner skips its assets (OM-5 fail-closed) and the
// deliverer refuses to apply through it. Toggling restores it to active. Signed into the
// ledger as a governance action.
func (d Deps) handleQuarantineConnection(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Quarantined bool `json:"quarantined"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var conn *platform.Connection
	for i := range conns {
		if conns[i].ID == id {
			conn = &conns[i]
			break
		}
	}
	if conn == nil {
		writeJSON(w, http.StatusNotFound, errBody("connection not found"))
		return
	}
	// Restoring sets active; only a deliberate quarantine flips the status. (We don't
	// resurrect a genuinely revoked/degraded connection — that's an OAuth-health concern.)
	if body.Quarantined {
		conn.Status = platform.ConnQuarantined
	} else {
		conn.Status = platform.ConnActive
	}
	if err := d.Store.PutConnection(r.Context(), *conn); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		state := "restored"
		if body.Quarantined {
			state = "quarantined"
		}
		d.Recorder.Record("connection "+state, "quarantine",
			map[string]any{"tenant_id": tenantID, "connection_id": id, "kind": conn.Kind, "quarantined": body.Quarantined},
			"connection "+state)
	}
	conn.SecretRef = "" // never echo the sealed ref
	writeJSON(w, http.StatusOK, conn)
}
