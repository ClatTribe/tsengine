package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/cloudcdr"
)

// handleIngestCloudEvents is the cloud detection-and-response (CDR) ingest — the ACSP "observe live
// execution" capability for the cloud control plane. A connector (or the customer) POSTs normalized
// audit events (AWS CloudTrail / GCP Audit Logs / Azure Activity Log); the deterministic detector
// (public_resource_exposure, security_group_opened, root_console_login, iam_privilege_escalation,
// audit_logging_disabled) runs over them and emits findings into the SAME store the rest of the
// platform reads — so a bucket-just-made-public or a security-group-opened-to-the-world flows through
// issues / incidents / grc / hitl like any finding, in seconds rather than the hours a periodic
// posture scan would take. Mirrors the identity-events + runtime-events ingest. Tenant-scoped (body
// tenant ignored for isolation). LLM-free + grounded (§10); detection only, never blocks (§13).
func (d Deps) handleIngestCloudEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	// Accept a single event or an array.
	var events []cloudcdr.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		var one cloudcdr.Event
		if err2 := json.Unmarshal(raw, &one); err2 != nil {
			writeJSON(w, http.StatusBadRequest, errBody("body must be a cloud event or an array of them"))
			return
		}
		events = []cloudcdr.Event{one}
	}

	threats := cloudcdr.Detect(events)
	findings := cloudcdr.Findings(threats)
	stored := 0
	for _, f := range findings {
		f.ID = d.newID("cdr")
		if perr := d.Store.PutFinding(r.Context(), tenantID, f); perr != nil {
			respond(w, nil, perr)
			return
		}
		stored++
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("cloud control-plane threats detected", "cloud_cdr",
			map[string]any{"tenant_id": tenantID, "events": len(events), "threats": stored}, "CDR ingest")
	}
	writeJSON(w, http.StatusOK, map[string]any{"events_ingested": len(events), "threats_detected": stored, "threats": threats})
}
