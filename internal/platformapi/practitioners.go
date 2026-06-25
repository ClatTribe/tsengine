package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// practitioners.go records WHO provides the human-in-the-loop for a tenant — the service model
// (self_serve | msp | managed) and the named experts of record. This is the difference between the
// two product GTM models: the MSP's expert (capacity=msp) vs. our delivery expert (capacity=managed)
// vs. the tenant's own team (internal). Tenant-scoped + stored on the Tenant (no secret), like Contacts.

func validServiceModel(s string) bool {
	switch s {
	case platform.ServiceSelfServe, platform.ServiceMSP, platform.ServiceManaged:
		return true
	}
	return false
}

func validCapacity(c string) bool {
	switch c {
	case platform.CapacityInternal, platform.CapacityMSP, platform.CapacityManaged:
		return true
	}
	return false
}

// handleGetPractitioners returns the tenant's service model + practitioners of record.
func (d Deps) handleGetPractitioners(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	model := t.ServiceModel
	if model == "" {
		model = platform.ServiceSelfServe
	}
	ps := append([]platform.Practitioner(nil), t.Practitioners...)
	if ps == nil {
		ps = []platform.Practitioner{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_model": model, "practitioners": ps})
}

// handleSetServiceModel sets who provides the HITL for the tenant.
func (d Deps) handleSetServiceModel(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		ServiceModel string `json:"service_model"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	model := strings.TrimSpace(body.ServiceModel)
	if !validServiceModel(model) {
		writeJSON(w, http.StatusBadRequest, errBody("service_model must be one of: self_serve, msp, managed"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	t.ServiceModel = model
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("service model set", "service_model",
			map[string]any{"tenant_id": tenantID, "service_model": model}, "HITL provider model updated")
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_model": model})
}

// handleAddPractitioner appends a named practitioner of record. name + a valid capacity are required.
func (d Deps) handleAddPractitioner(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Name       string   `json:"name"`
		Firm       string   `json:"firm"`
		Credential string   `json:"credential"`
		Capacity   string   `json:"capacity"`
		Email      string   `json:"email"`
		Scope      []string `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name := strings.TrimSpace(body.Name)
	capacity := strings.TrimSpace(body.Capacity)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name is required"))
		return
	}
	if !validCapacity(capacity) {
		writeJSON(w, http.StatusBadRequest, errBody("capacity must be one of: internal, msp, managed"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	id := "prac-" + tenantID
	if d.NewID != nil {
		id = "prac-" + d.NewID()
	}
	p := platform.Practitioner{
		ID:         id,
		Name:       name,
		Firm:       strings.TrimSpace(body.Firm),
		Credential: strings.TrimSpace(body.Credential),
		Capacity:   capacity,
		Email:      strings.TrimSpace(body.Email),
		Scope:      body.Scope,
	}
	t.Practitioners = append(t.Practitioners, p)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleDeletePractitioner removes a practitioner of record by id.
func (d Deps) handleDeletePractitioner(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := make([]platform.Practitioner, 0, len(t.Practitioners))
	found := false
	for _, p := range t.Practitioners {
		if p.ID == id {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("practitioner not found"))
		return
	}
	t.Practitioners = kept
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
