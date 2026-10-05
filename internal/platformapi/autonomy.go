package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/autonomy"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// autonomy.go: earned autonomy — the owner sees which kinds of fix have closed their kind of finding
// every time, and may let those apply without a per-action approval (internal/autonomy).

// handleGetAutonomy returns the offers and every grant's live state. Readable by any seat: knowing what
// runs without approval is part of knowing what the agents are allowed to do.
func (d Deps) handleGetAutonomy(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	acts, err := d.Store.ListActions(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, autonomy.Evaluate(tenantID, acts, t.AutonomyGrants, autonomy.OptionsFromEnv()))
}

// handleSetAutonomy grants or withdraws earned autonomy for one (class, remediation type). Owner-only by
// the /v1/settings/ prefix. A grant is REFUSED unless the record qualifies at this moment — the offer is
// what the record earned, and this endpoint does not let a click substitute for it.
func (d Deps) handleSetAutonomy(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Class           string `json:"class"`
		RemediationType string `json:"remediation_type"`
		Allow           bool   `json:"allow"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	body.Class, body.RemediationType = strings.TrimSpace(body.Class), strings.TrimSpace(body.RemediationType)
	if body.Class == "" || body.RemediationType == "" {
		writeJSON(w, http.StatusBadRequest, errBody("class and remediation_type are required"))
		return
	}
	ctx := r.Context()
	t, err := d.Store.GetTenant(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	kept := t.AutonomyGrants[:0:0]
	for _, g := range t.AutonomyGrants {
		if g.Class != body.Class || g.RemediationType != body.RemediationType {
			kept = append(kept, g)
		}
	}
	by := d.actorName(r)
	event := "earned autonomy withdrawn"
	if body.Allow {
		acts, err := d.Store.ListActions(ctx, tenantID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		closed, ok, why := autonomy.Qualifies(tenantID, acts, body.Class, body.RemediationType, autonomy.OptionsFromEnv())
		if !ok {
			writeJSON(w, http.StatusConflict, errBody("This fix has not earned autonomy for this kind of finding: "+why+"."))
			return
		}
		kept = append(kept, platform.AutonomyGrant{Class: body.Class, RemediationType: body.RemediationType,
			GrantedBy: by, GrantedAt: nowUTC(), BasisClosed: closed})
		event = "earned autonomy granted"
	}
	t.AutonomyGrants = kept
	if err := d.Store.PutTenant(ctx, t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record(event, "autonomy_grant", map[string]any{"tenant_id": tenantID, "class": body.Class,
			"remediation_type": body.RemediationType, "by": by, "allow": body.Allow},
			event+": "+body.RemediationType+" for "+body.Class+" by "+by)
	}
	acts, _ := d.Store.ListActions(ctx, tenantID)
	writeJSON(w, http.StatusOK, autonomy.Evaluate(tenantID, acts, t.AutonomyGrants, autonomy.OptionsFromEnv()))
}
