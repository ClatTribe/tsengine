package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestTriageStats_Funnel(t *testing.T) {
	// 10 raw findings:
	//  - 2 excluded by a path glob (test/*)
	//  - of the remaining 8: a CVE reported by 3 tools (3 findings → 1 confirmed issue,
	//    so 2 deduped), plus 5 distinct findings (5 issues)
	//  - 1 of those issues is suppressed (ignored)
	// The CVE rides in the rule id (UnifiedIssues parses it from rule/title).
	f := func(id, rule, ep, tool string, sev types.Severity) types.Finding {
		return types.Finding{ID: id, RuleID: rule, Endpoint: ep, Tool: tool, Severity: sev, Title: rule}
	}
	findings := []types.Finding{
		f("e1", "sast::x", "test/a.go", "semgrep", types.SeverityHigh), // excluded
		f("e2", "sast::y", "test/b.go", "semgrep", types.SeverityHigh), // excluded
		f("c1", "sca::CVE-2024-0001", "pkg", "trivy", types.SeverityCritical),
		f("c2", "sca::CVE-2024-0001", "pkg", "grype", types.SeverityCritical),
		f("c3", "sca::CVE-2024-0001", "pkg", "osv", types.SeverityCritical),
		f("d1", "web::sqli", "/a", "nuclei", types.SeverityHigh),
		f("d2", "web::xss", "/b", "dalfox", types.SeverityMedium),
		f("d3", "api::bola", "/c", "nuclei", types.SeverityHigh),
		f("d4", "secret::key", "/d", "gitleaks", types.SeverityHigh),
		f("d5", "iac::open", "/e", "checkov", types.SeverityMedium), // this one we'll suppress
	}
	excl := []platform.ExclusionRule{{Field: "path", Pattern: "test/*"}}

	// The suppressed issue's dedup key is "rule|<lower rule>|<lower endpoint>".
	ignored := map[string]bool{"rule|iac::open|/e": true}

	got := TriageStats(findings, excl, ignored)

	if got.RawFindings != 10 {
		t.Errorf("raw = %d, want 10", got.RawFindings)
	}
	if got.Excluded != 2 {
		t.Errorf("excluded = %d, want 2", got.Excluded)
	}
	if got.Deduped != 2 {
		t.Errorf("deduped = %d, want 2 (the CVE's 3 findings → 1 issue)", got.Deduped)
	}
	if got.Suppressed != 1 {
		t.Errorf("suppressed = %d, want 1 (the ignored iac issue's raw finding)", got.Suppressed)
	}
	// 8 kept → 6 issues (1 CVE + 5 distinct); 1 suppressed → 5 actionable.
	if got.ActionableIssues != 5 {
		t.Errorf("actionable = %d, want 5", got.ActionableIssues)
	}
	if got.ConfirmedIssues != 1 {
		t.Errorf("confirmed = %d, want 1 (the 3-tool CVE)", got.ConfirmedIssues)
	}
	// auto_triaged = 2 excluded + 2 deduped + 1 suppressed = 5 → 50%.
	if got.AutoTriaged != 5 {
		t.Errorf("auto_triaged = %d, want 5", got.AutoTriaged)
	}
	if got.AutoTriageRate < 0.499 || got.AutoTriageRate > 0.501 {
		t.Errorf("auto_triage_rate = %.3f, want 0.50", got.AutoTriageRate)
	}

	// Empty input → zero rate, no divide-by-zero.
	if z := TriageStats(nil, nil, nil); z.AutoTriageRate != 0 || z.RawFindings != 0 {
		t.Errorf("empty funnel = %+v, want zeros", z)
	}
}
