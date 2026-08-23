package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The fix axis — remediation-capture — is the half of "AI Security Engineer: find + fix" that had no
// recorded number anywhere (ADR 0024 C15). `tsbench defense` produces one, and it currently reads
// 100% remediation across every scenario.
//
// A RATE WITH NO FLOOR UNDER ITS CORPUS IS THE VACUOUS-PASS SHAPE. 100% over five scenarios and 100%
// over one are the same number wearing the same words while the second means almost nothing, and
// nothing in the harness noticed a scenario disappearing: `tsbench defense` errors only on an EMPTY
// directory. This is the guard internal/accuracybench had to grow per-core case floors for, applied
// to the defensive corpus — §14.2 rule 5's corollary, that a corpus must not shrink.
//
// It deliberately calls the production loader rather than counting directories itself: a scenario
// whose scenario.json stopped parsing is gone from the benchmark just as surely as a deleted one,
// and a test that re-implements the walk would not see it.
func TestDefenseCorpus_DoesNotShrink(t *testing.T) {
	const floor = 5

	scenarios, err := loadDefenseScenarios(filepath.Join(repoRootForDefenseCorpus(t), "fixtures", "defense"))
	if err != nil {
		// FAIL, never skip: a missing fixture tree is exactly when this guard stops guarding, and a
		// skip is green (§14.2 rule 6).
		t.Fatalf("defensive scenario corpus is unreadable (%v) — the fix-axis number is computed over "+
			"it, so a rate reported without it means nothing", err)
	}
	if len(scenarios) < floor {
		t.Fatalf("defensive corpus has %d scenarios, below the recorded floor of %d. Remediation "+
			"capture is a RATE: it rises as the evidence behind it disappears, so a shrinking corpus "+
			"reports a better number for a weaker claim. If a scenario was deliberately retired, "+
			"lower the floor in the same commit and say why.", len(scenarios), floor)
	}
	// Each must be identifiable, or the per-scenario ledger cannot attribute a result to it.
	seen := map[string]bool{}
	for _, sc := range scenarios {
		if sc.ID == "" {
			t.Error("a scenario has no id; the ledger keys results by id, so its runs would merge into another's")
		}
		if seen[sc.ID] {
			t.Errorf("duplicate scenario id %q — two fixtures reporting under one id inflate its run count", sc.ID)
		}
		seen[sc.ID] = true
	}
}

func repoRootForDefenseCorpus(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file, so the fixture tree cannot be found")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}
