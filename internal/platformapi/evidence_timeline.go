package platformapi

import (
	"net/http"
)

// handleEvidenceHistory (GET /v1/compliance/{framework}/evidence-history) returns the CONTINUOUS-EVIDENCE
// timeline for a framework — the ordered posture snapshots + a continuity summary (fully-met ratio, the
// captured window). This is the SOC 2 Type II / ISO-surveillance "prove it held across the window"
// artifact the point-in-time EvidencePack can't give. Tenant-scoped (§18.2 inv. 2). Grounded (§10): every
// snapshot is a real captured posture; an un-monitored framework returns an empty timeline, never a
// fabricated "continuously compliant".
func (d Deps) handleEvidenceHistory(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("compliance posture unavailable"))
		return
	}
	tl, err := d.GRC.EvidenceTimeline(r.Context(), tenantID, r.PathValue("framework"))
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

// handleEvidenceCapture (POST /v1/compliance/{framework}/evidence/capture) records an on-demand evidence
// snapshot for a framework right now (minInterval 0 → always captures, so a manual "snapshot the posture"
// is never skipped). The continuous driver (runner.CaptureAllEvidence) captures automatically each pass;
// this is the manual complement. Grounded: an unassessed framework captures nothing (captured=false).
func (d Deps) handleEvidenceCapture(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody("compliance posture unavailable"))
		return
	}
	snap, captured, err := d.GRC.CaptureEvidenceSnapshot(r.Context(), tenantID, r.PathValue("framework"), 0)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"captured": captured, "snapshot": snap})
}
