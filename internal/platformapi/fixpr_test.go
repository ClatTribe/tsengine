package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestSourcePathOf: only a real repo-relative source location is patchable. A URL/host/ARN has no
// file, and an absolute or traversal path must never be fetched or written.
func TestSourcePathOf(t *testing.T) {
	cases := []struct{ endpoint, want string }{
		{"app/login.php:42", "app/login.php"},
		{"src/db/query.go:117", "src/db/query.go"},
		{"app/login.php", "app/login.php"}, // no line suffix
		{"https://acme.com/search?q=", ""}, // a web finding — nothing to patch
		{"arn:aws:s3:::bucket", ""},        // cloud
		{"/etc/passwd:1", ""},              // absolute — refuse
		{"../../../etc/passwd:1", ""},      // traversal — refuse
		{"somehost", ""},                   // no extension → not a file
		{"", ""},                           // nothing
	}
	for _, c := range cases {
		if got := sourcePathOf(types.Finding{Endpoint: c.endpoint}); got != c.want {
			t.Errorf("sourcePathOf(%q) = %q, want %q", c.endpoint, got, c.want)
		}
	}
}

// TestFixClassOf: the class hint must come from what the finding says — CWE first, else the rule.
func TestFixClassOf(t *testing.T) {
	if got := fixClassOf(types.Finding{CWE: []string{"CWE-89"}, RuleID: "semgrep::x"}); got != "CWE-89" {
		t.Errorf("want CWE first, got %q", got)
	}
	if got := fixClassOf(types.Finding{RuleID: "semgrep::sqli"}); got != "semgrep::sqli" {
		t.Errorf("want rule fallback, got %q", got)
	}
	if got := fixClassOf(types.Finding{}); got != "vulnerability" {
		t.Errorf("want a safe default, got %q", got)
	}
}
