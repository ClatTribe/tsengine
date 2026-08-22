package bench

import (
	"strings"
	"testing"
)

func entry(mode, id string, pass bool, rate float64, expected, found int) DefenseLedgerEntry {
	return DefenseLedgerEntry{
		Mode: mode, ScenarioID: id, Pass: pass, RemediationRate: rate,
		ExpectedPaths: expected, FoundPaths: found,
	}
}

// Path recall defaulted to 1.0 when a run had no paths to find, and BestPath took the max — so ONE
// pathless run gave a scenario a permanent 100%, and it outranked every real measurement forever.
//
// Measured against the checked-in ledger when this was written: public-storage-exposure and
// stale-admin-account each had 9 runs, exactly ONE of which had a path to find, and that run found
// 0 of 1. Real path recall 0%. Both reported 100%.
func TestSummarizeDefenseLedger_APathlessRunIsNotPerfectRecall(t *testing.T) {
	sum := SummarizeDefenseLedger([]DefenseLedgerEntry{
		entry("substrate", "public-storage-exposure", true, 1.0, 0, 0), // nothing to find
		entry("substrate", "public-storage-exposure", true, 1.0, 1, 0), // a path, and it was missed
	})
	m := sum["substrate"]
	if got := m.BestPath["public-storage-exposure"]; got != 0 {
		t.Errorf("best path recall = %.2f, want 0 — the engine found none of the paths it was given, "+
			"and a run with nothing to find must not outrank that", got)
	}
	if !m.HasPaths["public-storage-exposure"] {
		t.Error("a scenario that DID have paths in at least one run must report a real recall")
	}
}

// A scenario that never had paths reports no recall at all, rather than a perfect 0-of-0.
func TestSummarizeDefenseLedger_NoPathsEverIsNotARecallNumber(t *testing.T) {
	sum := SummarizeDefenseLedger([]DefenseLedgerEntry{
		entry("substrate", "high-severity-noise", false, 1.0, 0, 0),
	})
	if sum["substrate"].HasPaths["high-severity-noise"] {
		t.Fatal("this scenario never had a path to find")
	}
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{entry("substrate", "high-severity-noise", false, 1.0, 0, 0)})
	if strings.Contains(out, "| 100% |") && !strings.Contains(out, "no paths to find") {
		t.Error("0-of-0 rendered as a perfect score")
	}
}

// The decoy scenario closes every closeable finding — rate 100% — while FAILING every run, because
// closing the decoys is the failure it exists to detect. Rate and pass answered different questions
// and only the rate was shown, so the headline read green for a scenario that has never passed.
func TestRenderDefenseLedger_ShowsRunsPassedBesideTheRate(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "high-severity-noise", false, 1.0, 0, 0),
		entry("substrate", "high-severity-noise", false, 1.0, 0, 0),
	})
	if !strings.Contains(out, "Runs passed") {
		t.Fatal("the table must carry a pass column")
	}
	if !strings.Contains(out, "| 0/2 |") {
		t.Errorf("a scenario that never passed must say so next to its 100%% rate:\n%s", out)
	}
}

// A lift between two arms that both fail every run is a delta between two failures.
func TestRenderDefenseLedger_MarksAScenarioNeitherArmPasses(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "high-severity-noise", false, 1.0, 0, 0),
		entry("agent", "high-severity-noise", false, 1.0, 0, 0),
	})
	if !strings.Contains(out, "never passed in either arm") {
		t.Errorf("a +0%% lift between two failing arms must be marked:\n%s", out)
	}
}
