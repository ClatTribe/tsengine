package platformapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// contacts.go is the per-tenant on-call escalation roster — the people the escalation matrix names
// (the contractual "escalation matrix with contact number"). Contact PII (email/phone), not a bearer
// secret, so stored plain on the Tenant. Live SMS/voice paging stays gated (Bucket C); this is the
// roster + numbers that make the escalation matrix name real humans.

// handleListContacts returns the roster, ordered by escalation precedence then name.
func (d Deps) handleListContacts(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	out := append([]platform.Contact(nil), t.Contacts...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	if out == nil {
		out = []platform.Contact{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAddContact validates + appends a contact. name required; at least one of email/phone.
func (d Deps) handleAddContact(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Name  string `json:"name"`
		Role  string `json:"role"`
		Email string `json:"email"`
		Phone string `json:"phone"`
		Order int    `json:"order"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	name := strings.TrimSpace(body.Name)
	email := strings.TrimSpace(body.Email)
	phone := strings.TrimSpace(body.Phone)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name is required"))
		return
	}
	if email == "" && phone == "" {
		writeJSON(w, http.StatusBadRequest, errBody("at least one of email or phone is required"))
		return
	}
	if email != "" && !strings.Contains(email, "@") {
		writeJSON(w, http.StatusBadRequest, errBody("email is not valid"))
		return
	}

	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	id := "ct-" + tenantID
	if d.NewID != nil {
		id = "ct-" + d.NewID()
	}
	c := platform.Contact{ID: id, Name: name, Role: strings.TrimSpace(body.Role), Email: email, Phone: phone, Order: body.Order}
	t.Contacts = append(t.Contacts, c)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("escalation contact added", "contact",
			map[string]any{"tenant_id": tenantID, "contact_id": c.ID, "name": c.Name}, "on-call roster updated")
	}
	writeJSON(w, http.StatusOK, c)
}

// handleDeleteContact removes a contact by id. Tenant-scoped.
func (d Deps) handleDeleteContact(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := make([]platform.Contact, 0, len(t.Contacts))
	found := false
	for _, c := range t.Contacts {
		if c.ID == id {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errBody("contact not found"))
		return
	}
	t.Contacts = kept
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("escalation contact removed", "contact",
			map[string]any{"tenant_id": tenantID, "contact_id": id}, "on-call roster updated")
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
