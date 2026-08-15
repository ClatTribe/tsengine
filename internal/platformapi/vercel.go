package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/vercelposture"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleVercelIngest is the deployment-platform posture ingest.
//
// A Series A company ships on Vercel, and its exposures are covered by nothing else here: they are
// not cloud-IAM misconfigurations, not code findings, and no scanner will find them because the
// surface IS the platform's own configuration. The headline one — an unprotected preview deployment
// publishing production-like code on every pull request — is close to invisible without reading the
// project settings directly.
//
// A connector (or the customer) POSTs the project snapshot; vercelposture.Assess surfaces grounded
// findings into the same store, so they flow through issues / incidents / grc / hitl like any other.
// Grounded + LLM-free: a well-configured account yields zero. The live fetcher (the Vercel API, with
// a token the customer pastes) is the credential-gated half; the posted-snapshot path works today,
// mirroring the OSINT / SaaS-posture / TPRM / device ingests.
func (d Deps) handleVercelIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var snap vercelposture.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid Vercel snapshot: "+err.Error()))
		return
	}

	findings := vercelposture.Assess(snap, vercelposture.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("vp") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		if d.GRC != nil {
			_ = d.GRC.Apply(r.Context(), tenantID, f)
		}
		saved = append(saved, f)
		stored++
	}
	// Findings that arrive by ingest reach the approval desk too — the same remediate.Propose
	// the runner uses for engine-scanned findings. Nil ProposeFix/Submitter → no-op.
	d.proposeForFindings(r.Context(), tenantID, saved)
	if d.IncidentOpener != nil && stored > 0 {
		_, _ = d.IncidentOpener.OpenFor(r.Context(), tenantID, saved, nil)
	}
	if d.Recorder != nil && stored > 0 {
		d.Recorder.Record("vercel posture assessed", "deployment_platform",
			map[string]any{"tenant_id": tenantID, "projects": len(snap.Projects), "findings": stored},
			"vercel project-snapshot ingest")
	}

	if findings == nil {
		findings = []types.Finding{}
	}
	resp := map[string]any{
		"projects": len(snap.Projects), "issues_detected": stored, "findings": findings,
	}
	// Say which projects we could not judge, rather than letting a clean result read as a clean
	// account. The assessor deliberately stays silent on settings a snapshot did not carry (§10 —
	// absent config is not insecure config), so silence about THAT silence is the one thing that
	// would make the refusal dishonest.
	notes := ingestNotes(len(snap.Projects), len(snap.Projects), "project", "projects", "")
	if incomplete := projectsMissingProtectionData(snap); len(incomplete) > 0 {
		notes = append(notes,
			"These projects did not report their deployment-protection settings, so we could not "+
				"judge them: "+joinNames(incomplete)+". An export without those fields is not a "+
				"clean bill of health — include them, or check Deployment Protection in each project.")
	}
	if len(notes) > 0 {
		resp["checks_not_run"] = notes
	}
	writeJSON(w, http.StatusOK, resp)
}

// projectsMissingProtectionData names projects whose snapshot omitted the protection settings, so the
// response can distinguish "configured correctly" from "we were never told".
func projectsMissingProtectionData(s vercelposture.Snapshot) []string {
	var out []string
	for _, p := range s.Projects {
		if p.Name == "" {
			continue
		}
		if p.PreviewProtected == nil && p.ProductionProtected == nil && p.PublicSource == nil {
			out = append(out, p.Name)
		}
	}
	return out
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
