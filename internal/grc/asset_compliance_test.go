package grc

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAssetCompliancePosture_GroundedAttribution(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "a-repo", Type: "repository", Target: "github.com/acme/api"},
		{ID: "a-clean", Type: "web_application", Target: "https://marketing.acme.com"},
	}
	findings := []types.Finding{
		// attributes to a-web (endpoint contains its target) + cites SOC2/PCI controls
		{ID: "f1", Severity: types.SeverityHigh, Endpoint: "https://app.acme.com/login?next=",
			Compliance: &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"6.2.4"}}},
		// also a-web, a different control on a critical sev → worst severity should win
		{ID: "f2", Severity: types.SeverityCritical, Endpoint: "https://app.acme.com/api/users",
			Compliance: &types.Compliance{SOC2: []string{"CC6.6"}}},
		// a repo file:line endpoint that contains NO asset target → NOT attributable
		{ID: "f3", Severity: types.SeverityMedium, Endpoint: "src/auth/login.go:42",
			Compliance: &types.Compliance{SOC2: []string{"CC8.1"}}},
	}

	got := AssetCompliancePosture(assets, findings)
	by := map[string]AssetPosture{}
	for _, p := range got {
		by[p.AssetID] = p
	}

	web := by["a-web"]
	if !web.Attributed || web.FindingCount != 2 {
		t.Fatalf("a-web: want attributed with 2 findings, got %+v", web)
	}
	// distinct (framework,control): soc2|CC6.1, pci|6.2.4, soc2|CC6.6 = 3
	if web.GapControls != 3 {
		t.Errorf("a-web gap controls: want 3 distinct, got %d", web.GapControls)
	}
	if web.WorstSeverity != string(types.SeverityCritical) {
		t.Errorf("a-web worst severity: want critical, got %q", web.WorstSeverity)
	}
	if len(web.Frameworks) != 2 { // soc2 + pci
		t.Errorf("a-web frameworks: want [pci soc2], got %v", web.Frameworks)
	}
	if !strings.Contains(web.Status, "not compliant") {
		t.Errorf("a-web with gaps should read 'not compliant', got %q", web.Status)
	}

	// the repo finding (f3) attributes to NO asset — a-repo stays unattributed + honest
	repo := by["a-repo"]
	if repo.Attributed || repo.FindingCount != 0 {
		t.Errorf("a-repo: file:line endpoint must NOT fabricate attribution, got %+v", repo)
	}
	if !strings.Contains(repo.Status, "not assessed at the asset level") {
		t.Errorf("a-repo status should be honest about no attribution, got %q", repo.Status)
	}

	// the clean web asset (no findings) must NEVER read as "compliant"
	clean := by["a-clean"]
	if strings.Contains(strings.ToLower(clean.Status), "compliant") && !strings.Contains(clean.Status, "not ") {
		// "not compliant"/"not a certification" wording is fine; a bare "compliant" is the bug
		t.Errorf("a-clean must not claim compliant, got %q", clean.Status)
	}

	// ordering: worst posture (a-web, 3 gaps) leads
	if got[0].AssetID != "a-web" {
		t.Errorf("worst-posture asset should sort first, got %q", got[0].AssetID)
	}
}
