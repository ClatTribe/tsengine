package repository

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE BUG. semgrep emits its endpoint as "path:line" whenever the result carries a line
// number, which is essentially always — and every language match here used HasSuffix, so
// "src/app.py:12" resolved to no language and the CodeQL dispatch was skipped. Silently:
// escalation is optional by design, so producing no dispatch is indistinguishable from a
// scan that found no injection. The trigger had never fired in production.
func TestCodeQLLangForPath_RealSemgrepEndpoints(t *testing.T) {
	for _, tc := range []struct{ endpoint, want string }{
		{"src/app.py", "python"},      // bare path (still works)
		{"src/app.py:12", "python"},   // what semgrep actually emits
		{"src/app.py:12:5", "python"}, // path:line:col
		{"a/b/Main.java:88", "java"},  // the same for every language
		{"web/x.ts:4", "javascript"},  //
		{"cmd/main.go:1", "go"},       //
		{"README.md:3", ""},           // an unmapped extension is still unmapped
		{"weird:notaline", ""},        // a colon that is not a line number is left alone
		{"path/to/file", ""},          // no extension at all
	} {
		if got := codeqlLangForPath(tc.endpoint); got != tc.want {
			t.Errorf("codeqlLangForPath(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}

// End to end through the trigger, with the endpoint format the scanner really produces.
func TestPlanEscalation_CodeQLFiresOnARealSemgrepFinding(t *testing.T) {
	f := types.Finding{RuleID: "semgrep::sqli", Tool: "semgrep", CWE: []string{"CWE-89"},
		Endpoint: "src/handlers/search.py:41"}
	var found bool
	for _, d := range (&Handler{}).PlanEscalation(types.Asset{}, nil, []types.Finding{f}) {
		if d.Tool.Name() == "codeql" {
			found = true
			if d.Args["language"] != "python" {
				t.Errorf("codeql dispatched with language %q, want python", d.Args["language"])
			}
		}
	}
	if !found {
		t.Error("a semgrep injection finding with a real path:line endpoint did not escalate to CodeQL")
	}
}

// The same suffix bug, one function over. It was PARTIAL here — the go.mod/go.sum Contains
// checks still matched an SCA finding on a manifest — which makes it harder to notice than
// the total failure in codeqlLangForPath: govulncheck fires on most Go repositories, and
// silently does not on one whose findings all sit in source files.
func TestIsGoProjectFinding_RealEndpoints(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		want     bool
	}{
		{"cmd/main.go", true},
		{"cmd/main.go:12", true},       // what semgrep/gosec actually emit
		{"internal/x/y.go:88:4", true}, // path:line:col
		{"go.mod", true},
		{"go.mod:3", true},       // already worked, via Contains
		{"src/app.py:12", false}, // still not a Go project
		{"README.md:1", false},
	} {
		if got := isGoProjectFinding(types.Finding{Endpoint: tc.endpoint}); got != tc.want {
			t.Errorf("isGoProjectFinding(%q) = %v, want %v", tc.endpoint, got, tc.want)
		}
	}
}
