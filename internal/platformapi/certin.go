package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/certin"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// annotateCERTIn stamps each incident's transient CERT-In six-hour reporting position
// (read-time only — never persisted, the same pattern as annotateSLA). An incident is
// annotated ONLY when its opening finding carries a CERT-In Annexure I category, so an
// incident with no reporting duty shows nothing rather than a false "you are late to a
// regulator" alarm (§10). The reported/breach state is grounded on the persisted
// CertInReportedAt the human set when filing.
func (d Deps) annotateCERTIn(ctx context.Context, tenantID string, incs []platform.Incident) {
	cats := d.certInCategoriesByFinding(ctx, tenantID)
	if len(cats) == 0 {
		return
	}
	now := time.Now().UTC()
	for i := range incs {
		c := cats[incs[i].FindingID]
		if len(c) == 0 {
			continue
		}
		if st, ok := certin.Evaluate(incs[i], c, incs[i].CertInReportedAt, now); ok {
			st := st
			incs[i].CertIn = &st
		}
	}
}

// certInCategoriesByFinding builds findingID → CERT-In Annexure I categories from the
// tenant's stored findings' own compliance annotations (produced by the crosswalk). One
// pass, so annotating a whole incident list is a single findings read.
func (d Deps) certInCategoriesByFinding(ctx context.Context, tenantID string) map[string][]string {
	fs, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, f := range fs {
		if f.Compliance != nil && len(f.Compliance.CERTIn) > 0 {
			out[f.ID] = f.Compliance.CERTIn
		}
	}
	return out
}

// handleCERTInReport (GET) prepares the CERT-In filing DRAFT for one incident; (POST)
// records that a named human filed it (discharging the six-hour duty).
func (d Deps) handleCERTInReport(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	all, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var inc *platform.Incident
	for i := range all {
		if all[i].ID == id {
			inc = &all[i]
			break
		}
	}
	if inc == nil {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}
	cats := d.certInCategoriesByFinding(r.Context(), tenantID)[inc.FindingID]

	switch r.Method {
	case http.MethodGet:
		rep, ok := certin.Prepare(*inc, cats, time.Now().UTC())
		if !ok {
			// Not a reportable incident → no draft, and say so plainly rather than inventing one.
			writeJSON(w, http.StatusBadRequest, errBody("this incident is not a CERT-In Annexure I reportable category"))
			return
		}
		writeJSON(w, http.StatusOK, rep)

	case http.MethodPost:
		if !certin.Reportable(cats) {
			writeJSON(w, http.StatusBadRequest, errBody("this incident is not a CERT-In reportable category — nothing to file"))
			return
		}
		var body struct {
			By string `json:"by"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.By == "" {
			// A regulatory filing needs a named human on record (§18.4).
			writeJSON(w, http.StatusBadRequest, errBody("a filer name ('by') is required — a CERT-In report is filed by a named person"))
			return
		}
		if inc.CertInReportedAt.IsZero() {
			inc.CertInReportedAt = time.Now().UTC()
			inc.CertInReportedBy = body.By
			if err := d.Store.PutIncident(r.Context(), *inc); err != nil {
				respond(w, nil, err)
				return
			}
			if d.Recorder != nil {
				d.Recorder.Record("cert-in incident report filed", "incident",
					map[string]any{"tenant_id": tenantID, "incident_id": inc.ID, "by": body.By},
					"CERT-In six-hour reporting duty discharged by a named human")
			}
		}
		respond(w, inc, nil)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
