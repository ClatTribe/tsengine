package platformapi

import (
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// POST /v1/saas/okta/sync — LIVE Okta CONFIGURATION posture through the onboarded Okta connection's
// token: sign-on rules, password and MFA-enrollment policies, API tokens, ThreatInsight. The
// accounts half (who lacks MFA, who is a super admin) is internal/operate's; this is the org's
// policy half, which was absent — SCuBA's 0.993 covers M365 and Google, not Okta. The monitoring
// pass runs the same fetch (runner.syncOktaPosture); this is its on-demand twin.
func (d Deps) handleSyncSaaSOkta(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.OktaOrgURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, errBody("OKTA_ORG_URL is not set on this deployment, so Okta's policies cannot be read"))
		return
	}
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var ok *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnOkta {
			ok = &conns[i]
			break
		}
	}
	if ok == nil {
		writeJSON(w, http.StatusBadRequest, errBody("connect Okta first"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
		return
	}
	token, oerr := d.Vault.Open(ok.SecretRef)
	if oerr != nil || token == "" {
		writeJSON(w, http.StatusInternalServerError, errBody("could not resolve the Okta token"))
		return
	}

	org, ferr := sspm.FetchOktaPosture(r.Context(), d.OktaOrgURL, ok.Account, token, nil)
	if ferr != nil {
		writeJSON(w, http.StatusBadGateway, errBody(ferr.Error()))
		return
	}
	findings := sspm.AssessOkta(org, sspm.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	d.markPostureAssessed(r.Context(), tenantID, "sspm", time.Now().UTC())

	stored := 0
	folded := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		f.ID = d.newID("sspm")
		if serr := d.Store.PutFinding(r.Context(), tenantID, f); serr != nil {
			respond(w, nil, serr)
			return
		}
		stored++
		folded = append(folded, f)
	}
	d.foldIntoPosture(r.Context(), tenantID, folded)
	if d.Recorder != nil {
		d.Recorder.Record("saas posture assessed (live)", "saas_posture",
			map[string]any{"tenant_id": tenantID, "provider": "okta", "source": "live", "org": org.Name, "findings": stored, "unread": len(org.Unread)},
			"live Okta configuration posture sync")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": "okta", "source": "live", "org": org.Name,
		"findings": findings, "count": len(findings),
		// What the token could not read, so zero findings is never mistaken for a hardened org.
		"unread": org.Unread,
	})
}
