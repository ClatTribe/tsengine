package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleDeleteConnection disconnects (removes) one of the tenant's connections — the founder
// self-serve fix for "I connected the wrong org / project". Tenant-scoped (only ever touches the
// authenticated tenant's connections), idempotent (deleting an absent id is a no-op success), and
// signed into the ledger as a governance action.
//
// This stops the platform acting through the connection going forward (the runner resolves assets
// per scan from live connections). Assets already discovered remain in the store with their history;
// removing the connection just halts future scans/actions through it. The sealed OAuth token in the
// store is dropped with the connection row (the SecretRef is never returned to the client anyway).
func (d Deps) handleDeleteConnection(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errBody("missing connection id"))
		return
	}

	// Look it up first so we can (a) 404 honestly when it isn't the tenant's, and (b) record the
	// kind in the ledger. ListConnections is tenant-scoped, so this also enforces isolation.
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var found *platform.Connection
	for i := range conns {
		if conns[i].ID == id {
			found = &conns[i]
			break
		}
	}
	if found == nil {
		writeJSON(w, http.StatusNotFound, errBody("connection not found"))
		return
	}

	if err := d.Store.DeleteConnection(r.Context(), tenantID, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("connection disconnected", "disconnect",
			map[string]any{"tenant_id": tenantID, "connection_id": id, "kind": found.Kind},
			"connection disconnected")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
