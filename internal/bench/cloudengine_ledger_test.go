package bench

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudEngineLedger_RoundTripAndSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ce-ledger.jsonl") // sub dir must be auto-created

	// three runs: two discriminating (a strong + a weak), one NON-discriminating (must not count).
	strong := CloudEngineEntry(1, 5, "frontier", ComputeL2Scorecard(2, 1, 2, 0), ComputeRemediationScore(2, 2, 2))
	weak := CloudEngineEntry(2, 5, "frontier", ComputeL2Scorecard(10, 4, 5, 0), ComputeRemediationScore(5, 5, 3))
	flat := CloudEngineEntry(3, 5, "frontier", ComputeL2Scorecard(2, 2, 2, 0), ComputeRemediationScore(2, 2, 2)) // substrate already 100% → non-discriminating
	for _, e := range []CloudEngineLedgerEntry{strong, weak, flat} {
		if err := AppendCloudEngineLedger(path, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	got, err := LoadCloudEngineLedger(path)
	if err != nil || len(got) != 3 {
		t.Fatalf("want 3 entries, got %d (err %v)", len(got), err)
	}

	s := SummarizeCloudEngineLedger(got)
	if s.Runs != 3 || s.Discriminating != 2 {
		t.Errorf("want 3 runs / 2 discriminating (the flat run doesn't count), got %d/%d", s.Discriminating, s.Runs)
	}
	if s.Grounded != 2 {
		t.Errorf("both discriminating runs invented nothing, want grounded 2, got %d", s.Grounded)
	}
	// median of {1.0 (strong), 0.5 (weak)} → the upper of the two at index len/2=1 = 1.0.
	if s.BestScore != 1.0 {
		t.Errorf("best score should be 1.0 (the strong run), got %v", s.BestScore)
	}
	// avg lift over discriminating: strong +1, weak +1 → 1.0.
	if s.AvgLift != 1.0 {
		t.Errorf("avg lift should be 1.0, got %v", s.AvgLift)
	}

	out := RenderCloudEngineLedger(got)
	if !strings.Contains(out, "discriminating (actually evaluated the agent): 2") {
		t.Errorf("render should report 2 discriminating runs, got:\n%s", out)
	}

	// a ledger with ONLY non-discriminating runs must say so (no agent score to report).
	empty := RenderCloudEngineLedger([]CloudEngineLedgerEntry{flat})
	if !strings.Contains(empty, "no discriminating runs yet") {
		t.Errorf("an all-non-discriminating ledger must flag it, got:\n%s", empty)
	}
}
