package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func repoAsset() platform.Asset {
	return platform.Asset{Type: "repository", TenantID: "ten-1", Target: "acme/api", Meta: map[string]string{"full_name": "acme/api"}}
}

// A leaked AWS key found in code gets the CROSS-SURFACE revoke directive (not just a code-scrub PR): the
// fix names aws_key_revoke + the key id, and the PR body leads with the revoke.
func TestPropose_LeakedAWSKey_AttachesRevoke(t *testing.T) {
	f := types.Finding{
		ID: "f-1", Tool: "gitleaks", RuleID: "gitleaks:aws-access-token", Severity: types.SeverityCritical,
		Title: "AWS access key committed to repository", Description: "found AKIAIOSFODNN7EXAMPLE in config.py",
		Endpoint: "config.py:12",
	}
	a, ok := Propose(f, repoAsset(), func() string { return "x" })
	if !ok {
		t.Fatal("expected an action")
	}
	if a.Kind != platform.ActOpenPR {
		t.Fatalf("a repo finding should still open a PR, got %v", a.Kind)
	}
	if a.Payload["remediation_type"] != rtypeKeyRevoke {
		t.Fatalf("leaked key should carry the aws_key_revoke directive, got %v", a.Payload["remediation_type"])
	}
	if a.Payload["key_id"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("key id should be extracted, got %v", a.Payload["key_id"])
	}
	body, _ := a.Payload["body"].(string)
	if !strings.Contains(body, "update-access-key") || !strings.Contains(strings.ToLower(body), "revoke") {
		t.Fatalf("PR body should lead with the revoke step, got:\n%s", body)
	}
}

// A redacted key (rule names it, value not in the text) still gets the revoke directive, with a generic
// placeholder and no invented key id.
func TestPropose_RedactedAWSKey_RevokeWithoutID(t *testing.T) {
	f := types.Finding{
		ID: "f-2", Tool: "trufflehog", RuleID: "AWS", Severity: types.SeverityHigh,
		Title: "AWS secret access key detected", Description: "verified AWS access key (value redacted)",
	}
	a, _ := Propose(f, repoAsset(), func() string { return "x" })
	if a.Payload["remediation_type"] != rtypeKeyRevoke {
		t.Fatalf("redacted AWS key should still carry the revoke directive, got %v", a.Payload["remediation_type"])
	}
	if _, hasID := a.Payload["key_id"]; hasID {
		t.Error("no concrete key id present → key_id must not be set (never invented)")
	}
	if body, _ := a.Payload["body"].(string); !strings.Contains(body, "<ACCESS_KEY_ID>") {
		t.Errorf("redacted key body should use the placeholder, got:\n%s", body)
	}
}

// A non-key repo finding gets the ordinary PR with NO cross-surface revoke directive.
func TestPropose_NonKeyRepoFinding_NoRevoke(t *testing.T) {
	f := types.Finding{
		ID: "f-3", Tool: "semgrep", RuleID: "semgrep:sql-injection", Severity: types.SeverityHigh,
		Title: "SQL injection in search handler", Endpoint: "handlers/search.go:40",
	}
	a, _ := Propose(f, repoAsset(), func() string { return "x" })
	if _, has := a.Payload["remediation_type"]; has {
		t.Errorf("a non-key finding must not carry a cloud revoke directive, got %v", a.Payload["remediation_type"])
	}
}

func TestIsLeakedAWSKeyFinding(t *testing.T) {
	cases := []struct {
		name string
		f    types.Finding
		want bool
	}{
		{"akia in desc", types.Finding{Description: "AKIAIOSFODNN7EXAMPLE"}, true},
		{"rule keyword", types.Finding{RuleID: "aws-access-key", Title: "AWS access key"}, true},
		{"generic secret", types.Finding{RuleID: "generic-api-key", Title: "API key"}, false},
		{"sqli", types.Finding{RuleID: "sql-injection"}, false},
	}
	for _, c := range cases {
		if got := isLeakedAWSKeyFinding(c.f); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}
