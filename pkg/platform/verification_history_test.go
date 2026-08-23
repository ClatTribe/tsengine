package platform

import "testing"

func vfy(status, disagreement string) FixVerification {
	return FixVerification{Status: status, Disagreement: disagreement, RescanSaidFixed: true}
}

// The append-only log must stay bounded, and the bound must not be reachable by routine operation:
// appends are change-only, so getting here needs dozens of genuine verdict FLIPS on one action.
func TestRecordVerification_HistoryIsBounded(t *testing.T) {
	var a Action
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			a.RecordVerification(vfy(FixStatusFixed, DisagreeRescanMissedLiveExploit))
		} else {
			a.RecordVerification(vfy("closed_with_proof", ""))
		}
	}
	if n := len(a.VerificationHistory); n != maxVerificationHistory {
		t.Fatalf("history must be capped at %d, got %d", maxVerificationHistory, n)
	}
	// The cap drops the OLDEST, so the most recent verdict is always present and current.
	last := a.VerificationHistory[len(a.VerificationHistory)-1]
	if a.Verification == nil || a.Verification.Status != last.Status {
		t.Error("the current verdict must match the newest history entry")
	}
}

// Current state and the log must never disagree: Verification is always the latest verdict, whether
// or not it was material enough to append.
func TestRecordVerification_CurrentAlwaysReflectsTheLatestVerdict(t *testing.T) {
	var a Action
	a.RecordVerification(vfy(FixStatusFixed, DisagreeRescanMissedLiveExploit))
	unchanged := vfy(FixStatusFixed, DisagreeRescanMissedLiveExploit)
	unchanged.Evidence = "a later pass, same verdict, different prose"
	a.RecordVerification(unchanged)

	if len(a.VerificationHistory) != 1 {
		t.Fatalf("an immaterial change must not append, got %d", len(a.VerificationHistory))
	}
	if a.Verification.Evidence != unchanged.Evidence {
		t.Error("...but the CURRENT verdict must still be the latest one, or the two views disagree")
	}
}
