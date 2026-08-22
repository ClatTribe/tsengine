package platformapi

import (
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleSyncSaaSGitHub is the LIVE GitHub-org SaaS-posture sync (Bucket A — WE FIX). The snapshot
// ingest (POST /v1/saas/github_org/snapshot) needs the customer to POST a config blob; this closes
// the live loop by fetching that config from the GitHub API itself, reusing the already-onboarded
// GitHub connection's token (no new credential). It finds the tenant's GitHub connection, resolves
// its sealed token, fetches the org posture, runs the same grounded AssessGitHubOrg, and stores the
// findings into the same store the rest of the platform reads — so they flow through issues /
// incidents / grc / hitl like any finding. A securely-config'd org yields zero findings (§10).
//
// What read:org can't see (per-member 2FA, installed apps, outside collaborators) stays the
// posted-snapshot path's job — honestly gated, never invented.
func (d Deps) handleSyncSaaSGitHub(w http.ResponseWriter, r *http.Request, tenantID string) {
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var gh *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnGitHub {
			gh = &conns[i]
			break
		}
	}
	if gh == nil {
		writeJSON(w, http.StatusBadRequest, errBody("connect a GitHub organization first"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
		return
	}
	token, oerr := d.Vault.Open(gh.SecretRef)
	if oerr != nil || token == "" {
		writeJSON(w, http.StatusInternalServerError, errBody("could not resolve the GitHub token"))
		return
	}

	snap, ferr := sspm.FetchGitHubOrg(r.Context(), d.GitHubAPIBase, gh.Account, token, nil)
	if ferr != nil {
		// surface the provider's error honestly (e.g. 403 insufficient scope) — never a false ok
		writeJSON(w, http.StatusBadGateway, errBody(ferr.Error()))
		return
	}
	findings := sspm.AssessGitHubOrg(snap, sspm.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	// RECORD THAT THIS RAN. sspm is grounded — a hardened estate yields ZERO findings — so
	// without the stamp "assessed and clean" and "never connected" are byte-identical in the
	// findings store, and the UI shows the reassuring reading for both (§10).
	d.markPostureAssessed(r.Context(), tenantID, "sspm", time.Now().UTC())

	stored := 0
	for _, f := range findings {
		f.ID = d.newID("sspm")
		if serr := d.Store.PutFinding(r.Context(), tenantID, f); serr != nil {
			respond(w, nil, serr)
			return
		}
		stored++
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("saas posture assessed (live)", "saas_posture",
			map[string]any{"tenant_id": tenantID, "provider": "github_org", "source": "live", "org": snap.Login, "findings": stored},
			"live GitHub org SSPM sync")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	resp := map[string]any{
		"provider": "github_org", "source": "live", "org": snap.Login,
		"findings_detected": stored, "findings": findings,
	}
	// THE LIVE PATH NEEDS THIS MOST. The onboarded token carries `read:org`, which cannot see
	// per-member 2FA, installed apps or outside collaborators — those fields come back empty BY
	// DESIGN, every sync, and the assessor is correctly silent about them. Without saying so, a
	// successful sync reporting zero findings reads as "your org is clean" when several checks were
	// never possible with the scope we hold.
	if note := sspm.UnassessedNote("github_org", snap); note != "" {
		resp["checks_not_run"] = []string{note}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSyncSaaSM365 is the LIVE Microsoft-365 SaaS-posture sync — the Graph twin of
// handleSyncSaaSGitHub. It reuses the already-onboarded M365 connection's token (no new
// credential), fetches the tenant's collaboration posture from Graph, runs the same
// grounded AssessM365, and stores the findings into the same store the rest of the
// platform reads, so they flow through issues / incidents / grc / hitl like any finding.
//
// This is the fetch half of the CISA SCuBA benchmark lane (internal/bench/scuba.go): the
// checks already existed but a real tenant had to hand-post a snapshot. What Graph cannot
// see — Teams meeting policies and Exchange transport posture (both PowerShell-only), and
// PIM assignment types (Entra ID P2) — stays the posted-snapshot path's job, honestly
// gated rather than invented. A partial read under-reports; it never over-reports (§10).
func (d Deps) handleSyncSaaSM365(w http.ResponseWriter, r *http.Request, tenantID string) {
	conns, err := d.Store.ListConnections(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	var ms *platform.Connection
	for i := range conns {
		if conns[i].Kind == platform.ConnM365 {
			ms = &conns[i]
			break
		}
	}
	if ms == nil {
		writeJSON(w, http.StatusBadRequest, errBody("connect a Microsoft 365 tenant first"))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusInternalServerError, errBody("secret vault unavailable"))
		return
	}
	token, oerr := d.Vault.Open(ms.SecretRef)
	if oerr != nil || token == "" {
		writeJSON(w, http.StatusInternalServerError, errBody("could not resolve the Microsoft 365 token"))
		return
	}

	snap, ferr := sspm.FetchM365Posture(r.Context(), d.GraphAPIBase, ms.Account, token, nil)
	if ferr != nil {
		// surface Graph's own error honestly (e.g. 403 insufficient scope) — never a false ok
		writeJSON(w, http.StatusBadGateway, errBody(ferr.Error()))
		return
	}
	findings := sspm.AssessM365(snap, sspm.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	// RECORD THAT THIS RAN. sspm is grounded — a hardened estate yields ZERO findings — so
	// without the stamp "assessed and clean" and "never connected" are byte-identical in the
	// findings store, and the UI shows the reassuring reading for both (§10).
	d.markPostureAssessed(r.Context(), tenantID, "sspm", time.Now().UTC())

	stored := 0
	for _, f := range findings {
		f.ID = d.newID("sspm")
		if serr := d.Store.PutFinding(r.Context(), tenantID, f); serr != nil {
			respond(w, nil, serr)
			return
		}
		stored++
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("saas posture assessed (live)", "saas_posture",
			map[string]any{"tenant_id": tenantID, "provider": "m365", "source": "live", "tenant": snap.Name, "findings": stored},
			"live Microsoft 365 SSPM sync")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": "m365", "source": "live", "tenant": snap.Name,
		"findings": findings, "count": len(findings),
	})
}
