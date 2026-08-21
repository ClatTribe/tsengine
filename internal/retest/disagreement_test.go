package retest

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

var dnow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func appliedWithRescan(keys []string, rescanFixed bool) platform.Action {
	a := platform.Action{ID: "a1", Status: platform.ActApplied, FindingKeys: keys}
	if rescanFixed {
		a.Verification = &platform.FixVerification{Status: platform.FixStatusFixed, Method: "rescan"}
	}
	return a
}

// THE CASE THIS EXISTS FOR. The scanner said gone; the exploit still runs. A customer was
// one step from being told they were safe, and that near-miss is the most valuable thing
// the system can learn from.
func TestApplyReattack_RescanSaidFixedButExploitLivesIsRecordedMachineReadably(t *testing.T) {
	out := ApplyReattack(
		[]platform.Action{appliedWithRescan([]string{"k1"}, true)},
		map[string]ReattackVerdict{"k1": {Exploitable: true, Verified: true, Evidence: "shell returned"}},
		dnow)
	if len(out) != 1 {
		t.Fatal("the action should have changed")
	}
	v := out[0].Verification
	if v.Status != StatusStillExploitable {
		t.Fatalf("a live exploit beats a scanner's silence, got %q", v.Status)
	}
	if !v.RescanSaidFixed {
		t.Fatal("what the absence check concluded must survive being overridden — it is half the lesson")
	}
	if v.Disagreement != platform.DisagreeRescanMissedLiveExploit {
		t.Fatalf("the conflict must be countable without regexing prose, got %q", v.Disagreement)
	}
}

// No disagreement when the rescan never claimed it was fixed: the exploit simply confirms
// what the scanner already said. Labelling that a conflict would inflate the corpus with
// non-examples.
func TestApplyReattack_NoDisagreementWhenTheRescanNeverClaimedClosure(t *testing.T) {
	out := ApplyReattack(
		[]platform.Action{appliedWithRescan([]string{"k1"}, false)},
		map[string]ReattackVerdict{"k1": {Exploitable: true, Verified: true}},
		dnow)
	if v := out[0].Verification; v.Disagreement != "" || v.RescanSaidFixed {
		t.Fatalf("the two methods agreed; there is nothing to learn here: %+v", v)
	}
}

// The other direction indicts a different method and must not be conflated with the
// dangerous one.
func TestApplyReattack_ScannerSeesVariantIsADistinctConflict(t *testing.T) {
	out := ApplyReattack(
		[]platform.Action{appliedWithRescan([]string{"k1"}, false)},
		map[string]ReattackVerdict{"k1": {Exploitable: false, Verified: true}},
		dnow)
	v := out[0].Verification
	if v.Disagreement != platform.DisagreeScannerSeesVariant {
		t.Fatalf("exploit closed but scanner still reporting is its own conflict, got %q", v.Disagreement)
	}
	if v.Disagreement == platform.DisagreeRescanMissedLiveExploit {
		t.Fatal("this one is not dangerous and must not be counted as if it were")
	}
}

func TestApplyReattack_BothMethodsAgreeingIsNotAConflict(t *testing.T) {
	out := ApplyReattack(
		[]platform.Action{appliedWithRescan([]string{"k1"}, true)},
		map[string]ReattackVerdict{"k1": {Exploitable: false, Verified: true}},
		dnow)
	v := out[0].Verification
	if v.Status != StatusClosedWithProof {
		t.Fatalf("agreement is the strongest claim available, got %q", v.Status)
	}
	if v.Disagreement != "" {
		t.Fatalf("nothing disagreed: %q", v.Disagreement)
	}
}
