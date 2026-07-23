package crossdetect

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestUnifiedIssues_AggregatesSSVC: the worst SSVC decision across a group's findings rides the issue.
func TestUnifiedIssues_AggregatesSSVC(t *testing.T) {
	findings := []types.Finding{
		{ID: "a", RuleID: "nuclei::CVE-2024-0001", Endpoint: "https://x/a", Severity: types.SeverityHigh, Tool: "nuclei",
			ThreatIntel: &types.ThreatIntel{SSVC: &types.SSVC{Decision: "attend"}}},
		{ID: "b", RuleID: "nuclei::CVE-2024-0001", Endpoint: "https://x/a", Severity: types.SeverityHigh, Tool: "grype",
			ThreatIntel: &types.ThreatIntel{SSVC: &types.SSVC{Decision: "act"}}}, // more urgent → wins
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 1 || issues[0].SSVC != "act" {
		t.Fatalf("group SSVC must be the worst (act), got %+v", issues)
	}
}

// TestPrioritize_ActLeadsWithinSeverity: two same-severity issues — the SSVC "act" one ranks above the
// "track"/none one; but SSVC never lifts a lesser-severity issue past a worse one.
func TestPrioritize_ActLeadsWithinSeverity(t *testing.T) {
	mk := func(id, ssvc string, sev types.Severity) types.Finding {
		var ti *types.ThreatIntel
		if ssvc != "" {
			ti = &types.ThreatIntel{SSVC: &types.SSVC{Decision: ssvc, DueDate: time.Time{}.Format("2006-01-02")}}
		}
		return types.Finding{ID: id, RuleID: "r::" + id, Endpoint: "https://x/" + id, Severity: sev, Tool: "nuclei", ThreatIntel: ti}
	}
	issues := UnifiedIssues([]types.Finding{
		mk("plain", "", types.SeverityHigh),
		mk("act", "act", types.SeverityHigh),
		mk("crit", "track", types.SeverityCritical),
	})
	ranked := PrioritizeByDataTier(issues, nil)

	// critical still leads (SSVC never crosses a severity band)
	if ranked[0].Endpoint != "https://x/crit" {
		t.Fatalf("critical must lead regardless of SSVC, got %s", ranked[0].Endpoint)
	}
	// within high, the act issue outranks the plain one
	var actRank, plainRank int
	for _, i := range ranked {
		if i.Endpoint == "https://x/act" {
			actRank = i.RiskRank
		}
		if i.Endpoint == "https://x/plain" {
			plainRank = i.RiskRank
		}
	}
	if actRank <= plainRank {
		t.Errorf("an SSVC 'act' issue must outrank a plain issue of the same severity: act=%d plain=%d", actRank, plainRank)
	}
}
