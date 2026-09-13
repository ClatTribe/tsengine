package platformapi

import (
	"net/http"
)

// POST /v1/identity/sync — read the connected identity providers' audit logs NOW and run the ITDR
// detector over them: the on-demand door of the same sync the monitoring pass runs
// (runner.SyncIdentityLogs), so the two cannot drift. POST /v1/identity/events remains the door for
// a customer-built pusher; this one needs nothing built.
//
// The response says which providers were read, which failed and why, how many events the window
// held, what the provider's log could not answer, and the findings stored. A run that read no
// provider is 503 with the reasons, never "0 findings".
func (d Deps) handleIdentitySync(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Runner == nil || len(d.Runner.IdentityLogFetchers) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "identity audit-log reading is not enabled on this deployment — ITDR runs on events posted to /v1/identity/events until it is",
			"reason": "identity_log_unavailable",
		})
		return
	}
	res, ran := d.Runner.SyncIdentityLogs(r.Context(), tenantID)
	if !ran {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "no identity provider's audit log could be read — connect Okta, Microsoft 365 or Google Workspace, or see `failed` for why a connected one was not readable",
			"reason": "identity_log_not_read",
			"failed": res.Failed,
		})
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("identity audit logs read and assessed", "identity_threat",
			map[string]any{"tenant_id": tenantID, "providers": res.Providers, "events": res.Events,
				"findings": len(res.Findings), "failed": res.Failed},
			"SOC 2 CC7.2 · ISO 27001 A.8.16 · NIST AU-6 monitoring of identity events")
	}
	writeJSON(w, http.StatusOK, res)
}
