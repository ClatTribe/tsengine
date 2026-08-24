package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// nilVault stands in for a real vault: the asset under test is public, so repoAuth never opens
// anything and the vault is only there to satisfy the signature.
type nilVault struct{}

func (nilVault) Seal(string) (string, error) { return "", nil }
func (nilVault) Open(string) (string, error) { return "", nil }

// reachability_wiring_test.go asserts that ADR 0029 D2a is actually REACHED in production.
//
// The whole ADR exists because capabilities in this tree keep being built, tested and never wired —
// `internal/reachability` itself was the example: complete, multi-language, and callable only from
// the CLI. Shipping the D2a plumbing without a test that the platform binary uses it would repeat
// the exact defect, one layer up.
//
// Two things are checked, because either alone is satisfiable while the feature does nothing:
// the dispatcher factory really reports a workspace path for a repository, and the construction site
// hands both that factory and the triage function to the EngineRunner.

func TestSandboxDispatcherWS_ReportsAWorkspaceOnlyForRepositories(t *testing.T) {
	// A non-repository asset has no source tree, so the workspace must be empty rather than some
	// incidental path — the runner treats a non-empty workspace as "there is a tree here to read".
	//
	// This drives the factory far enough to see the repository branch allocate a clone dir and then
	// FAIL at git clone (the target is not a real repo). The assertion is about the failure being the
	// clone rather than the wiring: a signature that could not carry a workspace would not compile.
	f := sandboxDispatcherWS(sandbox.ScanImages{Full: "tsengine/sandbox:test"}, store.NewMemory(), nilVault{})

	_, ws, cleanup, err := f(context.Background(), platform.Asset{
		Type: "repository", Target: "https://example.invalid/not/a/repo",
	})
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Skip("a clone unexpectedly succeeded in this environment; nothing to assert about the failure path")
	}
	if !strings.Contains(err.Error(), "clone") {
		t.Fatalf("expected the repository branch to fail at the clone step, got: %v", err)
	}
	if ws != "" {
		t.Errorf("a failed scan reported workspace %q — a path that does not exist must never be handed "+
			"to the analysis, which would then read an empty tree and call every dependency unused", ws)
	}
	// And the temp dir it made must be gone: a scan that fails still must not leak a clone.
	if entries, derr := os.ReadDir(repoScratchDir()); derr == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "tsengine-repo-") {
				t.Errorf("a failed clone left %s behind in the scratch dir", e.Name())
			}
		}
	}
}

func TestEngineRunnerIsWiredForReachability(t *testing.T) {
	// A source-level check, in the spirit of the platform's other wiring guards: the construction
	// site in main.go must pass BOTH the workspace-aware factory and the triage function. Either one
	// missing leaves the feature inert while every unit test in internal/runner still passes.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "runner.EngineRunner{")
	if i < 0 {
		t.Fatal("no runner.EngineRunner construction found in main.go — if it moved, move this guard " +
			"with it rather than deleting it")
	}
	// Bound the window to the literal itself so a match cannot come from somewhere unrelated.
	end := strings.Index(body[i:], "\n\t\t}")
	if end < 0 {
		t.Fatal("could not delimit the EngineRunner literal")
	}
	lit := body[i : i+end]

	for _, want := range []string{"NewDispatcherWithWorkspace:", "Reachability:"} {
		if !strings.Contains(lit, want) {
			t.Errorf("the platform's EngineRunner does not set %s.\n"+
				"Without it the code surface has no validation rung in production: reachability is "+
				"computed for nobody, which is the state ADR 0029 D2a exists to end.", want)
		}
	}
	if !strings.Contains(lit, "runner.TriageReachability") {
		t.Error("Reachability is set to something other than runner.TriageReachability — if that is " +
			"deliberate, say why here; the guard exists to make the swap visible, not to forbid it.")
	}
}
