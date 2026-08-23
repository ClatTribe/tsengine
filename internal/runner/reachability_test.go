package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// reachability_test.go covers ADR 0029 D2a: the code surface's validation rung, and — at least as
// importantly — everything it must refuse to say.

// tinyGoRepo writes a real, parseable Go module whose main() calls into an EXTERNAL dependency.
//
// External is the whole point: an SCA finding is about a third-party package, and the call graph
// records those as external references. An earlier version of this fixture used an intra-module
// package, which the extractor correctly records as a LOCAL call — so the test asked a question no
// real finding asks, and reported "unused" for code that was plainly called.
func tinyGoRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.22\n")
	write("main.go", "package main\n\nimport \"github.com/vendor/vulnpkg\"\n\nfunc main() { vulnpkg.Do() }\n")
	return root
}

func osvFinding(id, pkg, eco string) types.Finding {
	return types.Finding{
		ID: id, Tool: "osv-scanner", RuleID: "osv-scanner::CVE-2024-0001",
		Severity: types.SeverityHigh, Endpoint: pkg,
		Title:    "CVE-2024-0001 in " + pkg,
		ToolArgs: map[string]string{"ecosystem": eco},
	}
}

func TestTriageReachability_AnnotatesAReachableDependency(t *testing.T) {
	root := tinyGoRepo(t)
	in := []types.Finding{osvFinding("f1", "github.com/vendor/vulnpkg", "Go")}

	out := TriageReachability(root, in)

	if len(out) != 1 {
		t.Fatalf("triage must not add or drop findings, got %d", len(out))
	}
	if got := out[0].ToolArgs[ReachabilityKey]; got != "reachable" {
		t.Errorf("main() calls vuln.Do(), so this dependency is reachable; got %q", got)
	}
	if got := out[0].ToolArgs[ReachabilityFidelityKey]; got != "call_graph" {
		t.Errorf("a Go verdict comes from a resolved call graph and must say so; got %q", got)
	}
	if got := out[0].ToolArgs[ReachabilityScopeKey]; got != "package" {
		t.Errorf("the scope must be recorded as %q — our scanners report no vulnerable symbol, so this "+
			"is a package-level answer and must not be read as a function-level one; got %q", "package", got)
	}
	if !strings.Contains(out[0].Description, "reach this dependency") {
		t.Errorf("the human-readable note is missing from the description: %q", out[0].Description)
	}
}

func TestTriageReachability_NeverDowngradesTheFinding(t *testing.T) {
	// The dangerous direction. A dependency nothing calls is LOWER PRIORITY, not safe — the call
	// graph is an approximation and severity is the scanner's claim, not ours to overwrite.
	root := tinyGoRepo(t)
	in := []types.Finding{osvFinding("f2", "example.com/nobody/uses-this", "Go")}
	in[0].VerificationStatus = types.VerificationCorroborated

	out := TriageReachability(root, in)

	if got := out[0].ToolArgs[ReachabilityKey]; got == "reachable" {
		t.Fatalf("precondition: nothing imports this package, so it must not read as reachable; got %q", got)
	}
	if out[0].Severity != types.SeverityHigh {
		t.Errorf("severity was changed to %q. Reachability is a PRIORITY signal; silently down-ranking a "+
			"finding because a call graph could not see a path is the worst version of this feature.",
			out[0].Severity)
	}
	if out[0].VerificationStatus != types.VerificationCorroborated {
		t.Errorf("verification status was changed to %q. Reachability proves a path exists in the code, "+
			"not that the vulnerability is or is not exploitable.", out[0].VerificationStatus)
	}
	if !strings.Contains(out[0].Description, "not a dismissal") {
		t.Errorf("an unreachable verdict must say in words that the finding still stands: %q", out[0].Description)
	}
}

func TestTriageReachability_LeavesEverythingElseAlone(t *testing.T) {
	root := tinyGoRepo(t)
	cases := []struct {
		name string
		f    types.Finding
		why  string
	}{
		{
			name: "a SAST finding",
			f:    types.Finding{ID: "s1", Tool: "semgrep", RuleID: "semgrep::sqli", Endpoint: "app/db.go:12"},
			why:  "not a dependency finding; there is no package coordinate to ask about",
		},
		{
			name: "a trivy OS package",
			f: types.Finding{ID: "s2", Tool: "trivy", RuleID: "trivy::CVE-2024-9", Endpoint: "openssl",
				ToolArgs: map[string]string{"pkg": "openssl", "pkg_class": "os-pkgs"}},
			why: "an OS package has no application call graph to be reachable in — answering would be a " +
				"category error, not a near miss",
		},
		{
			name: "a web finding",
			f:    types.Finding{ID: "s3", Tool: "nuclei", RuleID: "nuclei::xss", Endpoint: "https://x.example/a"},
			why:  "a live endpoint, not a dependency",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := TriageReachability(root, []types.Finding{tc.f})
			if _, annotated := out[0].ToolArgs[ReachabilityKey]; annotated {
				t.Errorf("annotated %s — %s", tc.name, tc.why)
			}
		})
	}
}

func TestTriageReachability_RefusesRatherThanGuesses(t *testing.T) {
	in := []types.Finding{osvFinding("f3", "github.com/vendor/vulnpkg", "Go")}

	t.Run("no workspace", func(t *testing.T) {
		out := TriageReachability("", in)
		if _, annotated := out[0].ToolArgs[ReachabilityKey]; annotated {
			t.Error("annotated a finding with no source tree to analyse — an absent verdict is not a " +
				"claim, but a fabricated one is")
		}
	})

	t.Run("a tree with no graph in it", func(t *testing.T) {
		out := TriageReachability(t.TempDir(), in)
		if _, annotated := out[0].ToolArgs[ReachabilityKey]; annotated {
			t.Error("annotated a finding from an empty directory — we could not read the code, which is " +
				"not the same as finding no path through it")
		}
	})
}

func TestTriageReachability_DoesNotMutateTheCallersFindings(t *testing.T) {
	// The findings slice is the scan's own; a triage step that writes into it would silently change
	// what the caller already holds, and every caller here passes the same slice on to be stored.
	root := tinyGoRepo(t)
	in := []types.Finding{osvFinding("f4", "github.com/vendor/vulnpkg", "Go")}
	originalArgs := in[0].ToolArgs
	originalDesc := in[0].Description

	out := TriageReachability(root, in)

	if _, leaked := originalArgs[ReachabilityKey]; leaked {
		t.Error("the caller's ToolArgs map was mutated in place")
	}
	if in[0].Description != originalDesc {
		t.Error("the caller's finding description was mutated in place")
	}
	if out[0].Description == originalDesc {
		t.Error("...and the returned copy was not annotated, so nothing was gained by the copy")
	}
}
