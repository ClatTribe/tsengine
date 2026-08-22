package platformapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/sspm"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleIngestSaaSSnapshot is the SaaS-posture (SSPM) snapshot ingest — the live driver that was
// missing. The internal/sspm Assess* checks existed and were tested, but NOTHING in the running
// product called them, so connecting a SaaS app produced no posture findings. This endpoint closes
// that gap: a SaaS connector (or the customer) POSTs a provider's security-config snapshot to
// /v1/saas/{provider}/snapshot; the matching deterministic Assess runs and emits grounded findings
// into the SAME store the rest of the platform reads — so SaaS misconfigs flow through issues /
// incidents / grc / hitl like any other finding. Mirrors the identity-events ingest.
//
// Providers: github_org | slack | zoom | atlassian | salesforce | m365 | google_workspace. Tenant-scoped, LLM-free, grounded
// (§10) — a hardened app yields zero findings. The live admin-API fetcher (snapshot from the
// provider's API) is the credential-gated half; this makes the checks usable today with a posted
// snapshot (no external creds).
func (d Deps) handleIngestSaaSSnapshot(w http.ResponseWriter, r *http.Request, tenantID string) {
	provider := r.PathValue("provider")
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}

	findings, snapshot, perr := assessSaaSSnapshot(provider, raw)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, errBody(perr.Error()))
		return
	}

	findings = enrichFindings(findings) // L1.5 parity (§11)
	// RECORD THAT THIS RAN. sspm is grounded — a hardened estate yields ZERO findings — so
	// without the stamp "assessed and clean" and "never connected" are byte-identical in the
	// findings store, and the UI shows the reassuring reading for both (§10).
	d.markPostureAssessed(r.Context(), tenantID, "sspm", time.Now().UTC())
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		f.ID = d.newID("sspm")
		if serr := d.Store.PutFinding(r.Context(), tenantID, f); serr != nil {
			respond(w, nil, serr)
			return
		}
		// Fold the SaaS-config finding into the compliance posture (it already carries its control
		// mapping inline) — so a SaaS misconfig (no 2FA enforcement, public sharing, …) shows as a real
		// control gap in the founder's posture, not just a raw finding. Same wiring as the identity path.
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
		saved = append(saved, f)
		stored++
	}
	// Open an incident for any high-severity SaaS misconfig now (the scan-pass reconcile never sees
	// these ingested findings). Open-only, best-effort.
	// Findings that arrive by ingest reach the approval desk too — the same remediate.Propose
	// the runner uses for engine-scanned findings. Nil ProposeFix/Submitter → no-op.
	d.proposeForFindings(r.Context(), tenantID, saved)
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("saas posture assessed", "saas_posture",
			map[string]any{"tenant_id": tenantID, "provider": provider, "findings": stored}, "SSPM snapshot ingest")
	}
	if findings == nil {
		findings = []types.Finding{} // never serialize a nil slice as null
	}
	resp := map[string]any{"provider": provider, "findings_detected": stored, "findings": findings}
	// SAY WHICH SETTINGS THE SNAPSHOT DID NOT CARRY. Each assessor stays silent about a setting it
	// was not told about, so a near-empty snapshot produces zero findings and reads exactly like a
	// hardened tenant. That matters most here of all the ingests: GitHub's own live sync can only
	// read what `read:org` covers, so per-member 2FA and installed apps are routinely absent BY
	// DESIGN, and their absence must not be reported as a pass.
	if note := sspm.UnassessedNote(provider, snapshot); note != "" {
		resp["checks_not_run"] = []string{note}
	}
	writeJSON(w, http.StatusOK, resp)
}

// assessSaaSSnapshot decodes the provider's snapshot and runs its grounded SSPM checks. Returns a
// clear error for an unknown provider or an undecodable snapshot — never a silent empty result.
//
// It returns the DECODED snapshot as well, so the caller can say which settings it did not carry.
// Every assessor is deliberately silent about a setting the snapshot omitted (§10 — absent config is
// not insecure config), which means a near-empty snapshot yields zero findings and reads exactly
// like a hardened tenant. Handing the snapshot back is what lets the response tell those apart.
func assessSaaSSnapshot(provider string, raw []byte) ([]types.Finding, any, error) {
	switch provider {
	case "github_org", "github":
		var s sspm.GitHubOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid github_org snapshot: %v", err)
		}
		return sspm.AssessGitHubOrg(s, sspm.Options{}), s, nil
	case "slack":
		var s sspm.SlackWorkspace
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid slack snapshot: %v", err)
		}
		return sspm.AssessSlack(s, sspm.Options{}), s, nil
	case "zoom":
		var s sspm.ZoomAccount
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid zoom snapshot: %v", err)
		}
		return sspm.AssessZoom(s, sspm.Options{}), s, nil
	case "atlassian":
		var s sspm.AtlassianOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid atlassian snapshot: %v", err)
		}
		return sspm.AssessAtlassian(s, sspm.Options{}), s, nil
	case "salesforce":
		var s sspm.SalesforceOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid salesforce snapshot: %v", err)
		}
		return sspm.AssessSalesforce(s, sspm.Options{}), s, nil
	case "m365", "microsoft365":
		var s sspm.M365Tenant
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid m365 snapshot: %v", err)
		}
		return sspm.AssessM365(s, sspm.Options{}), s, nil
	case "google_workspace", "gworkspace", "google":
		var s sspm.GWorkspaceTenant
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("invalid google_workspace snapshot: %v", err)
		}
		return sspm.AssessGoogleWorkspace(s, sspm.Options{}), s, nil
	default:
		return nil, nil, fmt.Errorf("unknown SaaS provider %q (want: github_org | slack | zoom | atlassian | salesforce | m365 | google_workspace)", provider)
	}
}
