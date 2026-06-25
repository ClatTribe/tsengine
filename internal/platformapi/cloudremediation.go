package platformapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleSetCloudRemediation is the per-tenant cloud-remediation config (Bucket B — customer
// configuration, set via UX). Live cloud remediation writes into the CUSTOMER's account, so the
// cross-account write role is the customer's to provide — not an operator-global env var. This
// stores it on the customer's own cloud Connection.Config (a NON-secret identifier, like the
// account id), and the connector's Apply uses it at remediation time (connector.{AWS,GCP,Azure}
// .writerFor) instead of the operator default. Still HITL-gated (§18.2 inv. 3) and still needs the
// platform's cloud identity to assume/impersonate the role — so a wrong role surfaces honestly at
// Apply, never a false "done".
//
//	POST /v1/connections/{id}/cloud-remediation
//	{ "enabled": true, "role_arn": "arn:aws:iam::…:role/tsengine-remediate",   // AWS
//	  "region": "us-east-1", "impersonate_sa": "remediate@proj.iam.gserviceaccount.com" } // GCP
func (d Deps) handleSetCloudRemediation(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var body struct {
		Enabled       bool   `json:"enabled"`
		RoleARN       string `json:"role_arn"`
		Region        string `json:"region"`
		ImpersonateSA string `json:"impersonate_sa"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}

	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var conn *platform.Connection
	for i := range conns {
		if conns[i].ID == id {
			conn = &conns[i]
			break
		}
	}
	if conn == nil {
		writeJSON(w, http.StatusNotFound, errBody("connection not found"))
		return
	}
	switch conn.Kind {
	case platform.ConnAWS, platform.ConnGCP, platform.ConnAzure:
		// ok — a cloud connection
	default:
		writeJSON(w, http.StatusBadRequest, errBody("cloud-remediation config applies only to aws/gcp/azure connections"))
		return
	}
	// Provider-specific required field when enabling (so we never store a half-config that errors
	// only at Apply time, after a human approves).
	if body.Enabled {
		if conn.Kind == platform.ConnAWS && strings.TrimSpace(body.RoleARN) == "" {
			writeJSON(w, http.StatusBadRequest, errBody("role_arn is required to enable AWS remediation"))
			return
		}
		if conn.Kind == platform.ConnGCP && strings.TrimSpace(body.ImpersonateSA) == "" {
			writeJSON(w, http.StatusBadRequest, errBody("impersonate_sa is required to enable GCP remediation"))
			return
		}
	}

	if conn.Config == nil {
		conn.Config = map[string]string{}
	}
	if body.Enabled {
		conn.Config[platform.CfgRemediationEnabled] = "true"
	} else {
		conn.Config[platform.CfgRemediationEnabled] = "false"
	}
	setOrClear(conn.Config, platform.CfgRemediationRole, body.RoleARN)
	setOrClear(conn.Config, platform.CfgRemediationRegion, body.Region)
	setOrClear(conn.Config, platform.CfgRemediationSA, body.ImpersonateSA)

	if err := d.Store.PutConnection(r.Context(), *conn); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("cloud remediation configured", "cloud_remediation",
			map[string]any{"tenant_id": tenantID, "connection_id": id, "kind": conn.Kind, "enabled": body.Enabled},
			"per-tenant cloud-remediation role set")
	}
	conn.SecretRef = "" // never echo the sealed ref
	writeJSON(w, http.StatusOK, conn)
}

// setOrClear writes a trimmed value, or deletes the key when the value is empty (so a cleared
// field doesn't linger as a stale identifier).
func setOrClear(m map[string]string, key, val string) {
	if v := strings.TrimSpace(val); v != "" {
		m[key] = v
	} else {
		delete(m, key)
	}
}
