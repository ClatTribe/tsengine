package platformapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
// Providers: github_org | slack | zoom | atlassian | salesforce. Tenant-scoped, LLM-free, grounded
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

	findings, perr := assessSaaSSnapshot(provider, raw)
	if perr != nil {
		writeJSON(w, http.StatusBadRequest, errBody(perr.Error()))
		return
	}

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
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	// Open an incident for any high-severity SaaS misconfig now (the scan-pass reconcile never sees
	// these ingested findings). Open-only, best-effort.
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
	writeJSON(w, http.StatusOK, map[string]any{"provider": provider, "findings_detected": stored, "findings": findings})
}

// assessSaaSSnapshot decodes the provider's snapshot and runs its grounded SSPM checks. Returns a
// clear error for an unknown provider or an undecodable snapshot — never a silent empty result.
func assessSaaSSnapshot(provider string, raw []byte) ([]types.Finding, error) {
	switch provider {
	case "github_org", "github":
		var s sspm.GitHubOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid github_org snapshot: %v", err)
		}
		return sspm.AssessGitHubOrg(s, sspm.Options{}), nil
	case "slack":
		var s sspm.SlackWorkspace
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid slack snapshot: %v", err)
		}
		return sspm.AssessSlack(s, sspm.Options{}), nil
	case "zoom":
		var s sspm.ZoomAccount
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid zoom snapshot: %v", err)
		}
		return sspm.AssessZoom(s, sspm.Options{}), nil
	case "atlassian":
		var s sspm.AtlassianOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid atlassian snapshot: %v", err)
		}
		return sspm.AssessAtlassian(s, sspm.Options{}), nil
	case "salesforce":
		var s sspm.SalesforceOrg
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("invalid salesforce snapshot: %v", err)
		}
		return sspm.AssessSalesforce(s, sspm.Options{}), nil
	default:
		return nil, fmt.Errorf("unknown SaaS provider %q (want: github_org | slack | zoom | atlassian | salesforce)", provider)
	}
}
