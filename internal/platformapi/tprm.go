package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

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

	// The posted inventory WRITES THROUGH THE REGISTER rather than being assessed and discarded.
	// Before this the findings persisted and the portfolio did not, so a CI job could post twelve
	// vendors every night and nobody could answer "who are our vendors" the next morning. Both doors
	// now share saveVendors → assessRegister, so an inventory a job posts and a row a person adds
	// produce the same register and the same findings.
	for i := range req.Vendors {
		req.Vendors[i].Source = "ingest"
	}
	_, findings, serr := d.saveVendors(r.Context(), tenantID, req.Vendors, "TPRM vendor-inventory ingest")
	if serr != nil {
		respond(w, nil, serr)
		return
	}
	if findings == nil {
		findings = []types.Finding{}
	}

	resp := map[string]any{"vendors": len(req.Vendors), "risks_detected": len(findings), "findings": findings}
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
