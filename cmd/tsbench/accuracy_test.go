package main

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/accuracybench"
)

// EVERY regressed core must be named, not the first.
//
// Returning on the first made the second invisible until the first was fixed — a silent truncation
// of the very report this command exists to give. An operator should learn the whole extent of a
// regression in one run.
func TestAccuracyRegressions_NamesThemAll(t *testing.T) {
	err := regressionError([]accuracybench.CoreScore{
		{Core: "alpha", Recall: 0.80, Precision: 1.0, Cases: 10},
		{Core: "beta", Recall: 1.0, Precision: 1.0, Cases: 12},
		{Core: "gamma", Recall: 1.0, Precision: 0.50, Cases: 8},
	})
	if err == nil {
		t.Fatal("two cores regressed and no error was returned")
	}
	msg := err.Error()
	for _, want := range []string{"alpha", "gamma"} {
		if !strings.Contains(msg, want) {
			t.Errorf("regressed core %q not named: %q", want, msg)
		}
	}
	if strings.Contains(msg, "beta") {
		t.Errorf("a passing core was reported as regressed: %q", msg)
	}
	if !strings.Contains(msg, "2 core(s)") {
		t.Errorf("the count must state the extent: %q", msg)
	}
}

// All cores perfect → no error, so the check is not simply always-failing.
func TestAccuracyRegressions_CleanIsNil(t *testing.T) {
	if err := regressionError([]accuracybench.CoreScore{{Core: "a", Recall: 1, Precision: 1, Cases: 5}}); err != nil {
		t.Errorf("a clean scorecard reported a regression: %v", err)
	}
}
