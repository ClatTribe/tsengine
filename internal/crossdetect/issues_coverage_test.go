package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A coverage disclosure is the scan saying what it could NOT check. In a list titled
// "issues" it reads as one — sitting alongside real vulnerabilities, with CVE ids in its
// title, inviting exactly the conclusion its own text spends a paragraph refusing to make.
func TestUnifiedIssues_CoverageGapIsNotAnIssue(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://t/a", Severity: types.SeverityHigh, Title: "XSS"},
		{ID: "2", RuleID: asset.CoverageRulePrefix + "threat-informed-untested-cve", Tool: "coverage",
			Endpoint: "https://t", Severity: types.SeverityInfo,
			Title: "2 exploited CVE(s) against observed Apache httpd could not be tested"},
	}
	got := UnifiedIssues(findings)
	if len(got) != 1 {
		t.Fatalf("issues = %d, want 1 — the coverage disclosure must not become an issue: %+v", len(got), got)
	}
	if got[0].Title != "XSS" {
		t.Errorf("issue = %q, want the real finding", got[0].Title)
	}
}

// Excluding disclosures must not disturb ordinary grouping.
func TestUnifiedIssues_RealFindingsUnaffected(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Endpoint: "img", Severity: types.SeverityCritical, Title: "Log4Shell"},
		{ID: "2", RuleID: "trivy::CVE-2021-44228", Tool: "trivy", Endpoint: "img", Severity: types.SeverityCritical, Title: "Log4Shell"},
	}
	got := UnifiedIssues(findings)
	if len(got) != 1 || got[0].Count != 2 || !got[0].Confirmed {
		t.Errorf("two tools on one CVE must still merge and confirm: %+v", got)
	}
}
