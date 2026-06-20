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
