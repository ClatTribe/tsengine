package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/tprm"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// tprmRequest is the vendor inventory posted for a third-party-risk assessment.
type tprmRequest struct {
	Vendors []tprm.Vendor `json:"vendors"`
}

// handleTPRMIngest is the THIRD-PARTY / VENDOR RISK ingest — the Vanta-TPRM "finding issues" capability. A
// connector (or the customer) POSTs the vendor inventory; tprm.Assess surfaces grounded vendor-risk findings
// (a data-handling vendor with no SOC 2 / ISO 27001, a subprocessor with no DPA, a vendor with a known
// breach, a card-data vendor without PCI, a critical vendor overdue for review) and they land in the SAME
// store as every finding — flowing through issues / incidents / grc / hitl. The vendor portfolio is an
// asset class; this completes the "one-stop shop for security AND compliance" by analyzing it.
//
// Grounded + LLM-free: a well-managed portfolio yields zero findings. Mirrors the OSINT / SaaS / clouddrift
// ingest; a live TPRM connector (vendor-inventory sync from a procurement/SSO source) is the documented
// follow-on, the posted-inventory path works today.
func (d Deps) handleTPRMIngest(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req tprmRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid vendor inventory: "+err.Error()))
		return
	}

	findings := tprm.Assess(req.Vendors, tprm.Options{})
	findings = enrichFindings(findings) // L1.5 parity (§11)
	// Record that vendor risk was assessed — even (especially) when it came back clean, which is
	// otherwise indistinguishable from never having run.
	d.markPostureAssessed(r.Context(), tenantID, "tprm", time.Now().UTC())
	stored := 0
	saved := make([]types.Finding, 0, len(findings))
	for i, f := range findings {
		f.ID = d.newID("tprm") + "-" + strconv.Itoa(i)
		if err := d.Store.PutFinding(r.Context(), tenantID, f); err != nil {
			continue
		}
		d.foldIntoPosture(r.Context(), tenantID, []types.Finding{f})
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
		d.Recorder.Record("vendor risk assessed", "tprm",
			map[string]any{"tenant_id": tenantID, "vendors": len(req.Vendors), "findings": stored}, "TPRM vendor-inventory ingest")
	}
	if findings == nil {
		findings = []types.Finding{}
	}
	resp := map[string]any{"vendors": len(req.Vendors), "risks_detected": stored, "findings": findings}
	// Same honesty as the device ingest: an unnamed vendor is skipped, and a skipped vendor must not be
	// counted as a reviewed one. "0 risks across 12 vendors" is what someone puts in front of an auditor.
	names := make([]string, 0, len(req.Vendors))
	for _, v := range req.Vendors {
		names = append(names, v.Name)
	}
	if notes := ingestNotes(len(req.Vendors), countNamed(names), "vendor", "vendors",
		"they did not carry a vendor name"); len(notes) > 0 {
		resp["checks_not_run"] = notes
	}
	writeJSON(w, http.StatusOK, resp)
}
