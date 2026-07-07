package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/cloudcdr"
	"github.com/ClatTribe/tsengine/pkg/types"
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
	findings = enrichFindings(findings) // L1.5 parity (§11)
	saved := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		f.ID = d.newID("cdr")
		if perr := d.Store.PutFinding(r.Context(), tenantID, f); perr != nil {
			respond(w, nil, perr)
			return
		}
		saved = append(saved, f)
	}
	stored := len(saved)
	// Open incidents IMMEDIATELY for the live control-plane threats — that's the whole point of CDR
	// (detection-and-response in SECONDS, not the hours a periodic scan takes). Without this, a
	// root-console-login / SG-opened-to-the-world / IAM-privesc finding just sat in the store until the
	// next monitoring pass's Reconcile escalated it — defeating the real-time promise. Mirrors the drift,
	// identity-events, and OSINT ingest, which all open incidents on ingest via the same opener. High-sev
	// CDR threats cross the opener's floor; medium (new-credentials) opens per the floor. Grounded — the
	// finding IS the observed control-plane event.
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("cloud control-plane threats detected", "cloud_cdr",
			map[string]any{"tenant_id": tenantID, "events": len(events), "threats": stored}, "CDR ingest")
	}
	writeJSON(w, http.StatusOK, map[string]any{"events_ingested": len(events), "threats_detected": stored, "threats": threats})
}
