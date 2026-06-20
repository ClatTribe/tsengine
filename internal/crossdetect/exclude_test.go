package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"lodash", "lodash", true},
		{"lodash", "Lodash", true}, // case-insensitive
		{"lodash", "lodash-es", false},
		{"trivy::CVE-2021-*", "trivy::CVE-2021-23337", true},
		{"trivy::CVE-2021-*", "trivy::CVE-2022-0001", false},
		{"*/test/*", "src/test/foo.js", true},
		{"*.spec.js", "a/b/c.spec.js", true},
		{"*", "anything", true},
		{"semgrep::*::xss", "semgrep::js::xss", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestApplyExclusions(t *testing.T) {
	findings := []types.Finding{
		{ID: "f1", RuleID: "trivy::CVE-2021-23337", ToolArgs: map[string]string{"pkg": "lodash"}, Endpoint: "package.json"},
		{ID: "f2", RuleID: "semgrep::js::xss", Endpoint: "src/test/fixture.js"},
		{ID: "f3", RuleID: "semgrep::js::sqli", Endpoint: "src/app/db.js"},
		{ID: "f4", RuleID: "trivy::CVE-2020-0001", ToolArgs: map[string]string{"pkg": "express"}},
	}

	// Exclude the lodash package + everything under a test path.
	rules := []platform.ExclusionRule{
		{Field: platform.ExclByPackage, Pattern: "lodash"},
		{Field: platform.ExclByPath, Pattern: "*/test/*"},
	}
	got := ApplyExclusions(findings, rules)
	if len(got) != 2 {
		t.Fatalf("want 2 survivors (f3, f4), got %d: %+v", len(got), got)
	}
	if got[0].ID != "f3" || got[1].ID != "f4" {
		t.Errorf("wrong survivors: %s, %s", got[0].ID, got[1].ID)
	}

	// rule_id glob excludes by namespace.
	got2 := ApplyExclusions(findings, []platform.ExclusionRule{{Field: platform.ExclByRule, Pattern: "trivy::*"}})
	for _, f := range got2 {
		if f.RuleID[:5] == "trivy" {
			t.Errorf("trivy finding %s should have been excluded", f.ID)
		}
	}
	if len(got2) != 2 {
		t.Errorf("rule_id glob should leave the 2 semgrep findings, got %d", len(got2))
	}

	// No rules → input unchanged.
	if out := ApplyExclusions(findings, nil); len(out) != 4 {
		t.Errorf("no rules should pass all findings, got %d", len(out))
	}
	// A blank pattern is ignored (never excludes everything).
	if out := ApplyExclusions(findings, []platform.ExclusionRule{{Field: platform.ExclByAny, Pattern: "  "}}); len(out) != 4 {
		t.Errorf("a blank pattern must not exclude anything, got %d", len(out))
	}
}

func TestExclByCVE(t *testing.T) {
	f := types.Finding{ID: "f1", RuleID: "grype::GHSA-xxxx", Title: "lodash prototype pollution CVE-2021-23337"}
	rules := []platform.ExclusionRule{{Field: platform.ExclByCVE, Pattern: "CVE-2021-*"}}
	if out := ApplyExclusions([]types.Finding{f}, rules); len(out) != 0 {
		t.Errorf("CVE pulled from the title should match the cve exclusion, got %d survivors", len(out))
	}
}
