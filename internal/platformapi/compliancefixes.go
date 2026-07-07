package platformapi

import (
	"net/http"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// compliancefixes.go is the COMPLIANCE → REMEDIATION bridge — the "close the gap" glue an SMB owner needs.
// The compliance report already links each control GAP to the findings that cite it (grc.ReportRow.Evidence);
// the remediation layer already proposes Actions carrying the FindingIDs they resolve. This joins the two:
// for each gap control, how many of its findings ALREADY have a fix in the queue (proposed / pending / applied)
// and which action ids they are — so the page can say "CC6.1 gap · 3 findings · 2 fixes ready to approve →
// review in your inbox" instead of leaving the owner to hunt. Deterministic + grounded (§10): it only reports
// a fix that a real Action cites; it invents nothing and proposes nothing itself (the AI/remediate layer does).

// ControlFix is the fixability of one gap control.
type ControlFix struct {
	ControlID     string   `json:"control_id"`
	FindingCount  int      `json:"finding_count"`  // findings citing this control (from the report)
	FixableCount  int      `json:"fixable_count"`  // of those, how many have a remediation Action (any status)
	PendingCount  int      `json:"pending_count"`  // fixes awaiting the owner's approval (the actionable subset)
	AppliedCount  int      `json:"applied_count"`  // fixes already applied (progress)
	ActionIDs     []string `json:"action_ids,omitempty"`     // the actions that touch this control's findings
	PendingAction string   `json:"pending_action,omitempty"` // a representative pending action id (deep-link to inbox)
}

// ComplianceFixes is the per-framework bridge response.
type ComplianceFixes struct {
	Framework    string       `json:"framework"`
	GapControls  int          `json:"gap_controls"`
	FixableGaps  int          `json:"fixable_gaps"`  // gap controls with ≥1 fix in the queue
	PendingFixes int          `json:"pending_fixes"` // distinct actions awaiting approval across all gaps
	Controls     []ControlFix `json:"controls"`
}

// complianceFixStatus joins a compliance report's gap controls to the tenant's remediation actions. Pure +
// deterministic — the caller supplies both, so it never touches the store and is trivially testable.
func complianceFixStatus(framework string, rep grc.Report, actions []platform.Action) ComplianceFixes {
	// findingID → the actions that resolve it (a bulk action resolves many).
	byFinding := map[string][]platform.Action{}
	for _, a := range actions {
		ids := a.FindingIDs
		if len(ids) == 0 && a.FindingID != "" {
			ids = []string{a.FindingID}
		}
		for _, fid := range ids {
			byFinding[fid] = append(byFinding[fid], a)
		}
	}

	out := ComplianceFixes{Framework: framework}
	pendingSeen := map[string]bool{}
	for _, row := range rep.Rows {
		if !row.Gap {
			continue
		}
		out.GapControls++
		cf := ControlFix{ControlID: row.ControlID, FindingCount: len(row.Evidence)}
		seenAction := map[string]bool{}
		for _, ev := range row.Evidence {
			acts := byFinding[ev.FindingID]
			if len(acts) > 0 {
				cf.FixableCount++
			}
			for _, a := range acts {
				if seenAction[a.ID] {
					continue
				}
				seenAction[a.ID] = true
				cf.ActionIDs = append(cf.ActionIDs, a.ID)
				switch a.Status {
				case platform.ActPendingApproval:
					cf.PendingCount++
					if cf.PendingAction == "" {
						cf.PendingAction = a.ID
					}
					pendingSeen[a.ID] = true
				case platform.ActApplied:
					cf.AppliedCount++
				}
			}
		}
		if len(cf.ActionIDs) > 0 {
			out.FixableGaps++
		}
		out.Controls = append(out.Controls, cf)
	}
	out.PendingFixes = len(pendingSeen)
	return out
}

// handleComplianceFixes serves the bridge for a framework: which control gaps are fixable right now.
func (d Deps) handleComplianceFixes(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.GRC == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("grc not configured"))
		return
	}
	framework := r.PathValue("framework")
	if !grc.IsFramework(framework) {
		writeJSON(w, http.StatusNotFound, errBody("unknown compliance framework: "+framework))
		return
	}
	rep, err := d.GRC.Report(r.Context(), tenantID, framework)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	if rep == nil {
		writeJSON(w, http.StatusOK, ComplianceFixes{Framework: framework})
		return
	}
	actions, err := d.Store.ListActions(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	writeJSON(w, http.StatusOK, complianceFixStatus(framework, *rep, actions))
}
