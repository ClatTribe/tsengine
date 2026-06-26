package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// custom_frameworks.go is the bring-your-own-framework API (Sprinto/Vanta parity for the long tail). A
// tenant defines a framework whose controls map to signals tsengine already produces; its posture is
// DERIVED from live findings (grc.DeriveCustomPosture), never asserted — so it's as grounded + as honest
// (coverage, no false-compliant) as the built-in 22, with zero new detection code. Stored on the Tenant
// (no new store entity), like Contacts/Practitioners.

func (d Deps) handleListCustomFrameworks(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	cfs := t.CustomFrameworks
	if cfs == nil {
		cfs = []platform.CustomFramework{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"custom_frameworks": cfs})
}

func (d Deps) handleAddCustomFramework(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body platform.CustomFramework
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("name is required"))
		return
	}
	if len(body.Controls) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("at least one control is required"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	id := "cf-" + tenantID
	if d.NewID != nil {
		id = "cf-" + d.NewID()
	}
	body.ID = id
	for i := range body.Controls {
		if strings.TrimSpace(body.Controls[i].ID) == "" {
			body.Controls[i].ID = id + "-c" + itoa(i+1)
		}
	}
	t.CustomFrameworks = append(t.CustomFrameworks, body)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("custom framework added", "compliance",
			map[string]any{"tenant_id": tenantID, "framework_id": id, "controls": len(body.Controls)}, "bring-your-own-framework")
	}
	writeJSON(w, http.StatusOK, body)
}

func (d Deps) handleDeleteCustomFramework(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := t.CustomFrameworks[:0]
	for _, cf := range t.CustomFrameworks {
		if cf.ID != id {
			kept = append(kept, cf)
		}
	}
	t.CustomFrameworks = kept
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleCustomFrameworkPosture (GET /v1/custom-frameworks/{id}/posture) derives the framework's posture +
// coverage from the tenant's live findings — grounded, honest (never a false "compliant").
func (d Deps) handleCustomFrameworkPosture(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	var cf *platform.CustomFramework
	for i := range t.CustomFrameworks {
		if t.CustomFrameworks[i].ID == id {
			cf = &t.CustomFrameworks[i]
			break
		}
	}
	if cf == nil {
		writeJSON(w, http.StatusNotFound, errBody("custom framework not found"))
		return
	}
	findings, _ := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{})
	states, cov := grc.DeriveCustomPosture(*cf, findings)
	writeJSON(w, http.StatusOK, map[string]any{
		"framework": cf, "controls": states, "coverage": cov,
		"note": "Derived from your live findings — grounded, not a certification. Controls with no mapping (or no finding) need manual attestation.",
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
