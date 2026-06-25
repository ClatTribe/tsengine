package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestUnifiedIssues_MergesSameCVEAcrossScanners(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", RuleID: "trivy::CVE-2021-44228", Tool: "trivy", Severity: types.SeverityCritical, Title: "Log4Shell in log4j-core"},
		{ID: "2", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical, Title: "log4j-core RCE"},
		{ID: "3", RuleID: "govulncheck::CVE-2021-44228", Tool: "govulncheck", Severity: types.SeverityHigh, Title: "reachable log4j"},
		// An unrelated finding stays separate.
		{ID: "4", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Title: "SQL injection", Endpoint: "app.go:42"},
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 2 {
		t.Fatalf("want 2 unified issues, got %d: %+v", len(issues), issues)
	}

	// The Log4Shell issue is first (critical), confirmed by 3 tools, rolling up 3 findings.
	cve := issues[0]
	if cve.CVE != "CVE-2021-44228" {
		t.Errorf("first issue CVE = %q", cve.CVE)
	}
	if cve.Count != 3 {
		t.Errorf("count = %d, want 3", cve.Count)
	}
	if len(cve.Tools) != 3 || !cve.Confirmed {
		t.Errorf("expected 3 corroborating tools + confirmed, got %v", cve.Tools)
	}
	if cve.Severity != "critical" {
		t.Errorf("severity should be the worst across the group, got %q", cve.Severity)
	}
	if len(cve.FindingIDs) != 3 {
		t.Errorf("should roll up all 3 finding ids, got %v", cve.FindingIDs)
	}
}

func TestUnifiedIssues_DoesNotMergeDifferentIssues(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", RuleID: "nuclei::xss", Tool: "nuclei", Severity: types.SeverityMedium, Title: "XSS", Endpoint: "https://a/x"},
		{ID: "2", RuleID: "nuclei::xss", Tool: "nuclei", Severity: types.SeverityMedium, Title: "XSS", Endpoint: "https://a/y"},
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 2 {
		t.Errorf("different endpoints must stay separate issues, got %d", len(issues))
	}
	for _, i := range issues {
		if i.Confirmed {
			t.Errorf("a single-tool issue must not be 'confirmed': %+v", i)
		}
	}
}

func TestUnifiedIssues_CorroborationAcrossToolsOnSameLocation(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", RuleID: "secret::aws-key", Tool: "gitleaks", Severity: types.SeverityHigh, Title: "AWS key", Endpoint: "config.yml:3"},
		{ID: "2", RuleID: "secret::aws-key", Tool: "trufflehog", Severity: types.SeverityHigh, Title: "AWS key", Endpoint: "config.yml:3"},
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 1 {
		t.Fatalf("same rule+endpoint from 2 tools should merge, got %d", len(issues))
	}
	if !issues[0].Confirmed || len(issues[0].Tools) != 2 {
		t.Errorf("expected confirmed by gitleaks+trufflehog, got %+v", issues[0])
	}
}

func TestUnifiedIssues_MergesCVEFoundInDescription(t *testing.T) {
	// One scanner names the CVE in the title, another only in the description. They must merge
	// into ONE issue (the correlation FN fix), not two.
	findings := []types.Finding{
		{ID: "a", Tool: "trivy", Severity: types.SeverityHigh, RuleID: "trivy::CVE-2024-1234", Title: "CVE-2024-1234 in libfoo"},
		{ID: "b", Tool: "grype", Severity: types.SeverityHigh, RuleID: "grype::vuln", Title: "vulnerable libfoo", Description: "Matches CVE-2024-1234 in libfoo 1.2.3."},
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 1 {
		t.Fatalf("the same CVE (one in title, one in description) should merge to 1 issue, got %d", len(issues))
	}
	if !issues[0].Confirmed || len(issues[0].Tools) != 2 {
		t.Errorf("the merged issue should be confirmed by 2 tools, got %+v", issues[0].Tools)
	}
}

func TestUnifiedIssues_CasingVariantToolNotFalselyConfirmed(t *testing.T) {
	// The SAME tool reported under two casings must NOT flip Confirmed (which means ≥2 INDEPENDENT
	// tools). Same rule+endpoint so they group together.
	findings := []types.Finding{
		{ID: "a", Tool: "Trivy", Severity: types.SeverityHigh, RuleID: "r", Endpoint: "img:1"},
		{ID: "b", Tool: "trivy ", Severity: types.SeverityHigh, RuleID: "r", Endpoint: "img:1"},
	}
	issues := UnifiedIssues(findings)
	if len(issues) != 1 {
		t.Fatalf("same rule+endpoint should be one issue, got %d", len(issues))
	}
	if issues[0].Confirmed || len(issues[0].Tools) != 1 {
		t.Errorf("casing variants of one tool must count as 1 tool, not confirmed; got tools=%v confirmed=%v", issues[0].Tools, issues[0].Confirmed)
	}
}
