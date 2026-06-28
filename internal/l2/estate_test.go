package l2

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestBuildSystemPromptWithEstate: the L1.7 estate view (unified issues + attack paths) renders as the
// primary triage surface, severity-sorted + corroboration-tagged, and an EMPTY estate is byte-identical
// to the flat prompt (no behaviour change for callers that don't supply correlation).
func TestBuildSystemPromptWithEstate(t *testing.T) {
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://x"}
	l1 := []types.Finding{{ID: "f1", Severity: types.SeverityHigh, RuleID: "nuclei::xss", Endpoint: "/a", Title: "xss"}}
	estate := EstateContext{
		Issues: []IssueDigest{
			{Title: "SQL injection", Severity: "critical", Sources: []string{"sqlmap", "nuclei"}, Confirmed: true, Count: 3, Endpoint: "/login", CVE: "CVE-2024-1", Attacked: true},
			{Title: "weak TLS", Severity: "medium", Sources: []string{"tlsscan"}, Count: 1},
		},
		AttackPaths: []string{"[high] repository:repo → cloud_account:prod(crown)"},
	}
	p := BuildSystemPromptWithEstate(target, l1, estate)
	for _, want := range []string{
		"UNIFIED ISSUES", "SQL injection", "CONFIRMED by 2 tools", "UNDER ATTACK in prod",
		"CROSS-SURFACE ATTACK PATHS", "cloud_account:prod(crown)", "L1 findings (1)",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("estate prompt missing %q", want)
		}
	}
	// critical issue ordered before the medium one
	if strings.Index(p, "SQL injection") > strings.Index(p, "weak TLS") {
		t.Error("critical issue should render before the medium one")
	}
	// back-compat: empty estate == the flat prompt, and the flat prompt has no estate section.
	if BuildSystemPromptWithEstate(target, l1, EstateContext{}) != BuildSystemPrompt(target, l1) {
		t.Error("empty estate must equal the flat prompt (no behaviour change)")
	}
	if strings.Contains(BuildSystemPrompt(target, l1), "UNIFIED ISSUES") {
		t.Error("the flat prompt must not render the estate section")
	}
}
