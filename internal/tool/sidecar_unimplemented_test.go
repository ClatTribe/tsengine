package tool

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The sandbox→host findings SIDECAR is not implemented, and two documents described it as though it
// were — with a diagram, an arrow labelled "L1.5 hooks fire HERE", and a claim that the sidecar key is
// stripped before callers see it.
//
// Result.SandboxEmittedFindings is declared once, in this package, and written by NOTHING: no tool, no
// tool-server, not even a test. There is no sandbox-side tracer and Client.Execute calls no host
// tracer, so no key is ever set and none can be stripped.
//
// The real path is: a tool returns Result.Findings → the client returns the Result unchanged → the
// ASSET HANDLER's Normalize lifts them → l15.Enrich runs the hooks. That difference is load-bearing,
// because findings do NOT self-propagate: a new asset handler that omits the lift emits nothing, while
// the old diagram said the client did it for you.
//
// This test fails the moment someone implements the sidecar, which is exactly when CLAUDE.md §12.4 and
// arch.md need correcting back. It is a REMINDER attached to the change that would invalidate the
// documentation — not an argument that the sidecar should never be built.
func TestSandboxEmittedFindingsHasNoWriter(t *testing.T) {
	root := filepath.Join("..", "..")
	// A write looks like `X.SandboxEmittedFindings = …` or `SandboxEmittedFindings: …` in a literal.
	write := regexp.MustCompile(`SandboxEmittedFindings\s*(?::=|=[^=]|:\s)`)

	var writers []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && (info.Name() == "node_modules" || info.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "sidecar_unimplemented_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if write.Match(src) {
			writers = append(writers, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(writers) > 0 {
		t.Errorf("SandboxEmittedFindings is now written by %v — the sidecar has been implemented, so "+
			"CLAUDE.md §12.4 and arch.md's 'Sandbox → host findings propagation' section must be "+
			"corrected: both currently say it is NOT implemented, and that would now be the stale claim",
			writers)
	}
}
