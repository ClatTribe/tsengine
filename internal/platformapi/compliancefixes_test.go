package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestComplianceFixStatus_BridgesGapsToActions: the compliance→remediation bridge joins a control gap's
// citing findings to the tenant's remediation actions, so an SMB sees which gaps are fixable NOW. Grounded
// (§10): only a real Action counts as a fix; a gap with no action reads as not-yet-fixable.
func TestComplianceFixStatus_BridgesGapsToActions(t *testing.T) {
	rep := grc.Report{
		Rows: []grc.ReportRow{
			// CC6.1: two findings; f1 has a pending fix, f2 has none → fixable 1/2, 1 pending.
			{ControlID: "CC6.1", Gap: true, Evidence: []grc.ReportEvidence{
				{FindingID: "f1", Severity: types.SeverityHigh}, {FindingID: "f2", Severity: types.SeverityMedium}},
			},
			// CC7.2: one finding whose bulk fix was already applied → fixable 1, applied 1.
			{ControlID: "CC7.2", Gap: true, Evidence: []grc.ReportEvidence{{FindingID: "f3"}}},
			// CC8.1: a MET control (not a gap) must be ignored entirely.
			{ControlID: "CC8.1", Gap: false, Evidence: []grc.ReportEvidence{{FindingID: "f4"}}},
			// CC9.9: a gap with a finding that has NO action → not fixable.
			{ControlID: "CC9.9", Gap: true, Evidence: []grc.ReportEvidence{{FindingID: "f5"}}},
			// CC1.1: a gap whose only fix was REJECTED → must NOT read as fixable (a declined fix is not a fix).
			{ControlID: "CC1.1", Gap: true, Evidence: []grc.ReportEvidence{{FindingID: "f6"}}},
		},
	}
	actions := []platform.Action{
		{ID: "act-pending", Status: platform.ActPendingApproval, FindingID: "f1"},
		{ID: "act-applied", Status: platform.ActApplied, FindingIDs: []string{"f3"}}, // bulk action citing f3
		{ID: "act-rejected", Status: platform.ActRejected, FindingID: "f6"},          // declined — must not count
	}

	got := complianceFixStatus("soc2", rep, actions)
	if got.GapControls != 4 {
		t.Errorf("gap controls = %d, want 4 (met CC8.1 excluded)", got.GapControls)
	}
	if got.FixableGaps != 2 {
		t.Errorf("fixable gaps = %d, want 2 (CC6.1 + CC7.2)", got.FixableGaps)
	}
	if got.PendingFixes != 1 {
		t.Errorf("pending fixes = %d, want 1 (act-pending)", got.PendingFixes)
	}
	byID := map[string]ControlFix{}
	for _, c := range got.Controls {
		byID[c.ControlID] = c
	}
	if c := byID["CC6.1"]; c.FindingCount != 2 || c.FixableCount != 1 || c.PendingCount != 1 || c.PendingAction != "act-pending" {
		t.Errorf("CC6.1 = %+v, want 2 findings / 1 fixable / 1 pending / act-pending", c)
	}
	if c := byID["CC7.2"]; c.FixableCount != 1 || c.AppliedCount != 1 || c.PendingCount != 0 {
		t.Errorf("CC7.2 = %+v, want 1 fixable / 1 applied / 0 pending", c)
	}
	if c := byID["CC9.9"]; c.FixableCount != 0 || len(c.ActionIDs) != 0 {
		t.Errorf("CC9.9 must be not-fixable (no action), got %+v", c)
	}
	if c := byID["CC1.1"]; c.FixableCount != 0 || len(c.ActionIDs) != 0 {
		t.Errorf("CC1.1 must be not-fixable (its only fix was REJECTED), got %+v", c)
	}
	if _, ok := byID["CC8.1"]; ok {
		t.Error("a MET control must not appear in the gap bridge")
	}
}
