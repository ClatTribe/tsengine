package codesweep

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// Demo on real repo source (not a fixture): prove the decomposition points model calls at real sinks.
func TestDemo_PlanOverRealSource(t *testing.T) {
	repo, err := codelocalize.LoadRepo("../webagent", codelocalize.LoadOptions{})
	if err != nil || len(repo) == 0 {
		t.Skipf("source not available: %v", err)
	}
	tasks, err := Plan(context.Background(), codelocalize.HeuristicLocalizer{}, repo,
		PlanOptions{MaxFilesPerCWE: 2, MinConfidence: 0.6})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("repo files: %d  ->  focused tasks: %d", len(repo), len(tasks))
	for i, k := range tasks {
		if i >= 8 {
			t.Logf("  ... %d more", len(tasks)-8)
			break
		}
		t.Logf("  %-9s %-34s conf=%.2f lines=%v", k.CWE, k.Path, k.Confidence, k.SinkLines)
	}
	if len(tasks) == 0 {
		t.Error("expected focused tasks over real source")
	}
}
