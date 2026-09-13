package platformapi

import (
	"net/http"
)

// POST /v1/cloud/events/sync — read the connected AWS account's CloudTrail history NOW and run the
// CDR rules over it: the on-demand door of the same poll the monitoring pass runs
// (runner.SyncCloudEvents), so the two cannot drift. POST /v1/cloud/events remains the door for a
// customer-built forwarder; this one needs nothing built.
//
// The response says which connections were read, which failed and why, how many records the window
// held, what a truncated read left unexamined, the threats matched and the findings stored. A run
// that read no account is 503 with the reasons, never "0 threats".
func (d Deps) handleCloudEventsSync(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Runner == nil || d.Runner.CloudEventReader == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "CloudTrail polling is not enabled on this deployment — cloud CDR runs on events posted to /v1/cloud/events until it is",
			"reason": "cloudtrail_unavailable",
		})
		return
	}
	res, ran := d.Runner.SyncCloudEvents(r.Context(), tenantID)
	if !ran {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "no connected AWS account's CloudTrail could be read — connect an AWS account, or see `failed` for why a connected one was not readable",
			"reason": "cloudtrail_not_read",
			"failed": res.Failed,
		})
		return
	}
	// Open incidents immediately, as the posted-event door does: CDR's value is seconds, not a
	// monitoring interval. Detector.OpenFor is the same opener; Reconcile on the next pass dedups by key.
	if d.IncidentOpener != nil && len(res.Findings) > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, res.Findings, nil)
	}
	if d.Recorder != nil {
		d.Recorder.Record("cloudtrail read and assessed", "cloud_cdr",
			map[string]any{"tenant_id": tenantID, "connections": res.Connections, "records": res.Records,
				"threats": len(res.Threats), "failed": res.Failed, "unread": res.Unread},
			"SOC 2 CC7.2 · NIST AU-6 / SI-4 monitoring of the cloud control plane")
	}
	writeJSON(w, http.StatusOK, res)
}
