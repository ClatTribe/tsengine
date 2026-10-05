package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleResolveIncident is a person closing an incident, with the reason.
//
// It exists because some incidents can ONLY be closed this way. An event — a root console login, a
// password spray, a trail being stopped — happened; a later scan not seeing it again says nothing about
// whether anyone dealt with it, so the reconcile sweep never closes one (detect.IsEventProducer). Before
// this, there was no way to close them at all except waiting for that sweep to close them wrongly.
//
// A condition incident (an open bucket, a vulnerable package) can be closed here too, and if the issue is
// still present the next scan opens a fresh incident — which is the honest outcome of closing something
// that is not fixed.
//
// The closer is the signed-in person, never a typed name, and a reason is required: "closed" with no
// reason is indistinguishable from "dismissed without looking", and that is the record an auditor reads.
func (d Deps) handleResolveIncident(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body)
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		writeJSON(w, http.StatusBadRequest, errCode("say why it is being closed — investigated and benign, contained, or fixed", "reason_required"))
		return
	}
	by := "platform"
	if u, ok := d.actingUser(r); ok {
		by = u.Email
	}
	all, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	for _, inc := range all {
		if inc.ID != r.PathValue("id") {
			continue
		}
		if inc.Status == platform.IncidentResolved {
			respond(w, inc, nil) // idempotent
			return
		}
		now := time.Now().UTC()
		inc.Status, inc.ResolvedAt, inc.ResolvedBy, inc.ResolutionNote = platform.IncidentResolved, now, by, reason
		if inc.AcknowledgedAt.IsZero() {
			inc.AcknowledgedAt, inc.AcknowledgedBy = now, by // closing it is taking ownership of it
		}
		if err := d.Store.PutIncident(r.Context(), inc); err != nil {
			respond(w, nil, err)
			return
		}
		if d.Recorder != nil {
			d.Recorder.Record("incident resolved by a person", "incident",
				map[string]any{"tenant_id": tenantID, "incident_id": inc.ID, "by": by, "reason": reason,
					"event": detect.IsEventProducer(detect.ProducerOf(inc.RuleID))},
				"incident closed: "+reason)
		}
		respond(w, inc, nil)
		return
	}
	http.Error(w, "incident not found", http.StatusNotFound)
}
