package fieldevidence

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func contradiction() platform.FixVerification {
	return platform.FixVerification{Status: platform.FixStatusFixed, RescanSaidFixed: true,
		Disagreement: platform.DisagreeRescanMissedLiveExploit}
}
func agreement() platform.FixVerification {
	return platform.FixVerification{Status: "closed_with_proof", RescanSaidFixed: true}
}

// THE drift fix. Reading current state, an action contradicted in one pass and re-verified clean in a
// later one lost the contradiction entirely: ApplyReattack replaces Verification wholesale. That
// single action swung the corpus -1 contradicted / +1 clean, it biased toward TRUST, and it got
// stronger the more diligently a customer fixed things — erasing the one fact this corpus exists to
// remember.
func TestFromActions_AContradictionSurvivesALaterCleanVerification(t *testing.T) {
	a := platform.Action{FindingKeys: []string{"nuclei::sqli|https://x"}}
	a.RecordVerification(contradiction()) // pass 1: the re-scan was wrong
	a.RecordVerification(agreement())     // pass 5: the fix really landed

	got := FromActions("t1", []platform.Action{a})
	if len(got) != 2 {
		t.Fatalf("both labelled examples must survive, got %d: %+v", len(got), got)
	}
	var sawContradiction, sawClean bool
	for _, o := range got {
		if o.Contradicted {
			sawContradiction = true
		} else {
			sawClean = true
		}
	}
	if !sawContradiction {
		t.Error("the contradiction was erased by the later clean verdict — the drift this fixes")
	}
	if !sawClean {
		t.Error("the later clean verdict must count too")
	}
}

// The mirror risk: re-recording an unchanged verdict every monitoring pass would inflate the corpus
// with duplicates of ONE event — one action out-voting the estate instead of vanishing from it.
func TestRecordVerification_AppendsOnlyOnMaterialChange(t *testing.T) {
	a := platform.Action{FindingKeys: []string{"r1|e"}}
	for i := 0; i < 20; i++ {
		a.RecordVerification(contradiction()) // the same verdict, twenty passes running
	}
	if n := len(a.VerificationHistory); n != 1 {
		t.Fatalf("an unchanged verdict must not append, got %d entries", n)
	}
	if got := FromActions("t1", []platform.Action{a}); len(got) != 1 {
		t.Errorf("one event must yield one observation, got %d", len(got))
	}
	// ...but a real flip is a real event.
	a.RecordVerification(agreement())
	if n := len(a.VerificationHistory); n != 2 {
		t.Errorf("a changed verdict must append, got %d entries", n)
	}
}

// The migration case, and it is load-bearing. Every action written before the log existed has an
// empty history. Without the fallback the corpus silently empties itself on deploy and discards all
// accumulated evidence — a regression that surfaces as "we no longer distrust anything", which is
// indistinguishable from good news.
func TestFromActions_FallsBackToCurrentStateForPreLogActions(t *testing.T) {
	v := contradiction()
	legacy := platform.Action{FindingKeys: []string{"r1|e"}, Verification: &v} // no history at all
	got := FromActions("t1", []platform.Action{legacy})
	if len(got) != 1 || !got[0].Contradicted {
		t.Fatalf("a pre-log action must still count, got %+v", got)
	}
}
