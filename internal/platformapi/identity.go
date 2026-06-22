package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/identitythreat"
)

// handleIngestIdentityEvents is the real-time identity-threat (ITDR) ingest (ADR 0010 Phase 5
// wiring). An IdP connector (or the customer) POSTs identity audit events (Okta System Log /
// Google Admin / M365 audit); the deterministic detector (impossible_travel, privileged_grant,
// mfa_removed, password_spray) runs over them and emits findings into the SAME store the rest of
// the platform reads — so identity threats flow through issues / incidents / grc / hitl like any
// other finding. Mirrors the runtime-events ingest. Tenant-scoped (body tenant ignored for
// isolation). LLM-free + grounded (§10).
func (d Deps) handleIngestIdentityEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// Accept a single event or an array.
	var events []identitythreat.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		var one identitythreat.Event
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			writeJSON(w, http.StatusBadRequest, errBody("body must be an identity event or an array of them"))
			return
		}
		events = []identitythreat.Event{one}
	}

	threats := identitythreat.Detect(events, identitythreat.Config{})
	findings := identitythreat.Findings(threats)
	stored := 0
	for _, f := range findings {
		f.ID = d.newID("idt")
		if perr := d.Store.PutFinding(r.Context(), tenantID, f); perr != nil {
			respond(w, nil, perr)
			return
		}
		stored++
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("identity threats detected", "identity_threat",
			map[string]any{"tenant_id": tenantID, "events": len(events), "threats": stored}, "ITDR ingest")
	}
	writeJSON(w, http.StatusOK, map[string]any{"events_ingested": len(events), "threats_detected": stored, "threats": threats})
}
