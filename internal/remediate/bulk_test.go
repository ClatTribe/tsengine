package remediate

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func seqIDs() func() string {
	n := 0
	return func() string { n++; return strconv.Itoa(n) }
}

func TestProposeBulk_GroupsSCAByPackage(t *testing.T) {
	asset := platform.Asset{TenantID: "t1", Type: "repository", Target: "acme/app",
		ConnectionID: "c1", Meta: map[string]string{"full_name": "acme/app"}}
	findings := []types.Finding{
		{ID: "f1", RuleID: "trivy::CVE-1", Severity: types.SeverityHigh, ToolArgs: map[string]string{"pkg": "lodash", "installed_version": "4.17.0", "fixed_version": "4.17.19"}},
		{ID: "f2", RuleID: "trivy::CVE-2", Severity: types.SeverityCritical, ToolArgs: map[string]string{"pkg": "lodash", "installed_version": "4.17.0", "fixed_version": "4.17.21"}},
		{ID: "f3", RuleID: "trivy::CVE-3", Severity: types.SeverityMedium, ToolArgs: map[string]string{"pkg": "express", "installed_version": "4.18.0", "fixed_version": "4.18.2"}},
		{ID: "f4", RuleID: "semgrep::xss", Severity: types.SeverityHigh}, // no pkg → singleton
	}
	acts := ProposeBulk(findings, asset, seqIDs())

	// lodash(2)→1 bulk PR; express(1)→1 single; semgrep(1)→1 single = 3 actions.
	if len(acts) != 3 {
		t.Fatalf("want 3 actions (1 bulk + 2 single), got %d", len(acts))
	}
	var bulk *platform.Action
	for i := range acts {
		if len(acts[i].FindingIDs) >= 2 {
			bulk = &acts[i]
		}
	}
	if bulk == nil {
		t.Fatal("expected a bulk action covering the two lodash findings")
	}
	if bulk.FindingID != "f1" {
		t.Errorf("representative FindingID should be the first (f1), got %q", bulk.FindingID)
	}
	if len(bulk.FindingIDs) != 2 || bulk.FindingIDs[0] != "f1" || bulk.FindingIDs[1] != "f2" {
		t.Errorf("bulk should cite both findings in order, got %v", bulk.FindingIDs)
	}
	if bulk.Kind != platform.ActOpenPR {
		t.Errorf("bulk fix should be a PR, got %q", bulk.Kind)
	}
	// Title names the package + the highest fixed version (4.17.21 > 4.17.19, numeric).
	if !strings.Contains(bulk.Title, "lodash") || !strings.Contains(bulk.Title, "4.17.21") {
		t.Errorf("bulk title should name lodash → 4.17.21, got %q", bulk.Title)
	}
	body, _ := bulk.Payload["body"].(string)
	if !strings.Contains(body, "f1") || !strings.Contains(body, "f2") {
		t.Errorf("bulk body should list both findings, got %q", body)
	}
}

func TestProposeBulk_NonRepoFallsBackToSingle(t *testing.T) {
	// A non-repository asset has no multi-finding PR shape → every finding is proposed
	// singly (a ticket/config), never collapsed into a bulk PR.
	asset := platform.Asset{TenantID: "t1", Type: "cloud_account", Target: "aws-1", ConnectionID: "c1"}
	findings := []types.Finding{
		{ID: "f1", RuleID: "prowler::x", Severity: types.SeverityHigh},
		{ID: "f2", RuleID: "prowler::x", Severity: types.SeverityHigh},
	}
	acts := ProposeBulk(findings, asset, seqIDs())
	if len(acts) != 2 {
		t.Fatalf("non-repo should produce one action per finding, got %d", len(acts))
	}
	for _, a := range acts {
		if len(a.FindingIDs) != 0 {
			t.Errorf("non-repo actions must not be bulk, got FindingIDs %v", a.FindingIDs)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"4.17.19", "4.17.21", true},  // numeric, not lexical
		{"4.17.21", "4.17.19", false}, //
		{"1.2.0", "1.10.0", true},     // 2 < 10 numerically
		{"2.0.0", "2.0.0", false},     // equal
		{"1.0", "1.0.1", true},        // shorter is less when the extra segment is non-zero
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}
