package dockle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_SkipsPass(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob, "alpine:3.18")
	// FATAL + WARN + INFO = 3; PASS skipped.
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3 (PASS excluded)", len(findings))
	}
	bySev := map[types.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}
	if bySev[types.SeverityHigh] != 1 || bySev[types.SeverityMedium] != 1 || bySev[types.SeverityInfo] != 1 {
		t.Errorf("severity distribution wrong: %v", bySev)
	}
}

func TestNormalizeLevel(t *testing.T) {
	if normalizeLevel("FATAL") != types.SeverityHigh {
		t.Error("FATAL→high")
	}
	if normalizeLevel("PASS") != "" {
		t.Error("PASS should be dropped")
	}
	if normalizeLevel("SKIP") != "" {
		t.Error("SKIP should be dropped")
	}
}

func TestSurface(t *testing.T) {
	d := New()
	if d.Name() != "dockle" || !d.SandboxExecution() {
		t.Error("surface wrong")
	}
}
