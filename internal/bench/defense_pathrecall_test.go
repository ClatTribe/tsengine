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

// A lift table over a saturated substrate cannot measure a lift, and +0% then reads as "the agent
// adds nothing" when the true statement is "this bench cannot tell".
//
// The cloud-engine lane already carries this idea (clouddiscrimination.go: with no headroom "the run
// can't tell a great engineer from a mediocre one"). This lane — the one whose HERO metric IS the
// ablation — had no such check, while its substrate sat at 100% on all four scenarios.
func TestRenderDefenseLedger_SaysWhenTheAblationHasNoHeadroom(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "a", true, 1.0, 1, 1),
		entry("substrate", "b", true, 1.0, 1, 1),
		entry("agent", "a", true, 1.0, 1, 1),
	})
	if !strings.Contains(out, "No headroom") {
		t.Errorf("a saturated substrate must be disclosed, or +0%% reads as a verdict on the agent:\n%s", out)
	}
	if !strings.Contains(out, "cannot tell") {
		t.Error("and it must say what the +0% actually means")
	}
}

// With real headroom the notice must NOT fire — a permanent caveat is one nobody reads, and it would
// discredit a genuine +0% measured against a substrate that has room to be beaten.
func TestRenderDefenseLedger_NoNoticeWhenThereIsHeadroom(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "a", false, 0.5, 2, 1), // the substrate can be beaten here
		entry("agent", "a", true, 1.0, 2, 2),
	})
	if strings.Contains(out, "No headroom") {
		t.Errorf("this substrate scores 50%% — the agent's +50%% lift is a real measurement:\n%s", out)
	}
}

// Saturation is about PASSING, not about the remediation rate, and the difference is not academic:
// a scenario can close every closeable finding (rate 100%) and still FAIL because it also acted on a
// decoy. The first version of the headroom check used the rate, and therefore announced "no headroom"
// about a run the substrate had just failed — the exact error it exists to prevent, made by the check.
func TestRenderDefenseLedger_HeadroomIsMeasuredByPassesNotRate(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		// rate 100%, but it acted on a decoy, so pass=false → the substrate can still be beaten here.
		entry("substrate", "decoy-trap", false, 1.0, 0, 0),
		entry("agent", "decoy-trap", true, 1.0, 0, 0),
	})
	if strings.Contains(out, "No headroom") {
		t.Errorf("the substrate FAILS this scenario, so there is room for an agent to do better:\n%s", out)
	}
}

// A scenario one arm has never run has no comparison to make. Reading the missing arm's zero-valued
// map entry as a score produced "-100%" for a scenario the agent had simply never been given.
func TestRenderDefenseLedger_NoPhantomLiftForAnArmThatNeverRan(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "brand-new", true, 1.0, 1, 1),
		entry("substrate", "shared", true, 1.0, 1, 1),
		entry("agent", "shared", true, 1.0, 1, 1),
	})
	if strings.Contains(out, "-100%") {
		t.Errorf("a fabricated regression for a scenario the agent never ran:\n%s", out)
	}
	if !strings.Contains(out, "has not run this scenario") {
		t.Errorf("the missing arm must be named rather than scored:\n%s", out)
	}
}

// The arm that DID run still needs its pass context. Without it the row read "substrate 100%" for a
// scenario the substrate had failed — the rate-without-pass problem fixed in the per-mode tables,
// surviving in the one branch that takes a different path.
func TestRenderDefenseLedger_NotRunRowStillCarriesPassContext(t *testing.T) {
	out := RenderDefenseLedgerMarkdown([]DefenseLedgerEntry{
		entry("substrate", "only-substrate-ran", false, 1.0, 1, 0), // rate 100%, never passed
		entry("substrate", "shared", true, 1.0, 1, 1),
		entry("agent", "shared", true, 1.0, 1, 1),
	})
	if !strings.Contains(out, "substrate has never passed it") {
		t.Errorf("a 100%% rate for a scenario the substrate has never passed must say so, even on the "+
			"not-run row:\n%s", out)
	}
}
