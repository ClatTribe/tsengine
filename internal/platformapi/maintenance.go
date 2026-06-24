package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// maintenance.go is the per-tenant maintenance-window surface (change-freeze / deploy windows). While
// a window is active the detector opens no new incidents and the escalation matrix pages no one — the
// standard MDR/SOC "planned work shouldn't trip the on-call" control. No secret material, so windows
// are stored plain on the Tenant (like the escalation matrix and the SLA policy).

// handleListMaintenanceWindows returns the tenant's windows (empty slice, never null).
func (d Deps) handleListMaintenanceWindows(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	out := t.MaintenanceWindows
	if out == nil {
		out = []platform.MaintenanceWindow{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAddMaintenanceWindow validates + appends a window. starts_at must be before ends_at and the
// window must not already be in the past (ends_at in the future). Ledger-recorded.
func (d Deps) handleAddMaintenanceWindow(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Name     string    `json:"name"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
		Reason   string    `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name is required"))
		return
	}
	if body.StartsAt.IsZero() || body.EndsAt.IsZero() || !body.StartsAt.Before(body.EndsAt) {
		writeJSON(w, http.StatusBadRequest, errBody("starts_at must be before ends_at"))
		return
	}
	if body.EndsAt.Before(time.Now()) {
		writeJSON(w, http.StatusBadRequest, errBody("ends_at is in the past"))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	id := "mw-" + tenantID
	if d.NewID != nil {
		id = "mw-" + d.NewID()
	}
	win := platform.MaintenanceWindow{ID: id, Name: name, StartsAt: body.StartsAt.UTC(), EndsAt: body.EndsAt.UTC(), Reason: strings.TrimSpace(body.Reason)}
	t.MaintenanceWindows = append(t.MaintenanceWindows, win)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("maintenance window scheduled", "maintenance_window",
			map[string]any{"tenant_id": tenantID, "window_id": win.ID, "starts_at": win.StartsAt, "ends_at": win.EndsAt},
			"alerting suppressed during window")
	}
	writeJSON(w, http.StatusOK, win)
}

// handleDeleteMaintenanceWindow removes a window by id (cancel a planned/active freeze). Tenant-scoped.
func (d Deps) handleDeleteMaintenanceWindow(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := make([]platform.MaintenanceWindow, 0, len(t.MaintenanceWindows))
	found := false
	for _, win := range t.MaintenanceWindows {
		if win.ID == id {
			found = true
			continue
		}
		kept = append(kept, win)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("maintenance window not found"))
		return
	}
	t.MaintenanceWindows = kept
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("maintenance window cancelled", "maintenance_window",
			map[string]any{"tenant_id": tenantID, "window_id": id}, "alerting resumed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
