package cloudagent

import (
	"strings"
	"testing"
	"time"
)

const (
	snapA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	snapB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// DRIFT AND AGE ARE DIFFERENT CLAIMS and must never collapse (ADR 0024 C4).
//
// Drift is a fact about the world: the graph these permissions were evaluated against no longer
// exists, so the proof is void. Age is an admission about US: nothing observed has changed, but we
// have not re-asked. Treating age as invalidation throws away good evidence on a quiet estate;
// treating drift as mere age keeps asserting a proof about a graph that has been replaced.
func TestProofFreshness_Evaluate(t *testing.T) {
	const now = "2026-08-23T12:00:00Z"
	for _, tc := range []struct {
		name    string
		f       ProofFreshness
		current string
		want    Standing
	}{
		{
			name:    "unchanged and recent stands",
			f:       ProofFreshness{SnapshotHash: snapA, ObtainedAt: "2026-08-23T11:00:00Z"},
			current: snapA, want: StandingCurrent,
		},
		{
			name:    "the inventory changed underneath it",
			f:       ProofFreshness{SnapshotHash: snapA, ObtainedAt: "2026-08-23T11:00:00Z"},
			current: snapB, want: StandingInvalidated,
		},
		{
			name:    "unchanged but not re-asked in days",
			f:       ProofFreshness{SnapshotHash: snapA, ObtainedAt: "2026-08-01T11:00:00Z"},
			current: snapA, want: StandingUnverifiedSince,
		},
		{
			// Not knowing whether the ground moved is a different statement from knowing it did not.
			name:    "no current state to compare against",
			f:       ProofFreshness{SnapshotHash: snapA, ObtainedAt: "2026-08-23T11:00:00Z"},
			current: "", want: StandingUnknown,
		},
		{
			name:    "a proof with no provenance cannot be judged",
			f:       ProofFreshness{},
			current: snapA, want: StandingUnknown,
		},
		{
			name:    "an unreadable timestamp is unknown, not current",
			f:       ProofFreshness{SnapshotHash: snapA, ObtainedAt: "last tuesday"},
			current: snapA, want: StandingUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := tc.f.Evaluate(tc.current, at(now), 0)
			if got != tc.want {
				t.Fatalf("standing = %q, want %q (%s)", got, tc.want, why)
			}
			if strings.TrimSpace(why) == "" {
				t.Error("every standing must carry its reason — a verdict a reader cannot check is one they must take on trust")
			}
		})
	}
}

// Drift outranks age: an invalidated proof must not be softened into "unverified since" merely
// because it is also recent.
func TestProofFreshness_DriftBeatsRecency(t *testing.T) {
	f := ProofFreshness{SnapshotHash: snapA, ObtainedAt: "2026-08-23T11:59:00Z"}
	got, why := f.Evaluate(snapB, at("2026-08-23T12:00:00Z"), 0)
	if got != StandingInvalidated {
		t.Fatalf("a one-minute-old proof against a CHANGED account reported %q — recency is not relevance", got)
	}
	if !strings.Contains(why, "no longer exists") {
		t.Errorf("the reason must say the evaluated graph is gone; got %q", why)
	}
}

// A set of answers is only as fresh as its OLDEST member. Taking the newest would let one late probe
// make a stale batch look current.
func TestEarliestProbedAt_TakesTheOldestAnswer(t *testing.T) {
	got := earliestProbedAt([]ProbeRecord{
		{ProbedAt: "2026-08-23T11:00:00Z"},
		{ProbedAt: "2026-08-20T09:00:00Z"},
		{ProbedAt: ""}, // unstamped records are skipped, not treated as "now"
		{ProbedAt: "2026-08-22T10:00:00Z"},
	})
	if got != "2026-08-20T09:00:00Z" {
		t.Fatalf("effective proof time = %q, want the oldest answer", got)
	}
}

// The context hash identifies the QUESTION, so the same tuples asked in a different order are the
// same request — and a run that asked DIFFERENT questions is a different proof even if both say
// "confirmed".
func TestContextHash_IdentifiesTheQuestionNotTheOrderOrTheAnswer(t *testing.T) {
	a := []ProbeRecord{
		{Principal: "p1", Action: "s3:GetObject", Resource: "r1", Verdict: "ALLOW"},
		{Principal: "p2", Action: "iam:PassRole", Resource: "r2", Verdict: "DENY"},
	}
	reordered := []ProbeRecord{a[1], a[0]}
	if contextHashOf(a) != contextHashOf(reordered) {
		t.Error("the same tuples in a different order hashed differently — order is not part of the request")
	}

	// Same tuples, opposite answers: still the same QUESTION, so a re-run is comparable to the
	// original rather than trivially different for having got a different answer.
	answered := []ProbeRecord{
		{Principal: "p1", Action: "s3:GetObject", Resource: "r1", Verdict: "DENY"},
		{Principal: "p2", Action: "iam:PassRole", Resource: "r2", Verdict: "ALLOW"},
	}
	if contextHashOf(a) != contextHashOf(answered) {
		t.Error("the answers changed the hash — then a re-check could never be compared with what it re-checks")
	}

	different := append([]ProbeRecord{}, a...)
	different = append(different, ProbeRecord{Principal: "p3", Action: "sts:AssumeRole", Resource: "r3"})
	if contextHashOf(a) == contextHashOf(different) {
		t.Error("a run that asked an extra question hashed the same — two different proofs would be indistinguishable")
	}
	if contextHashOf(nil) != "" {
		t.Error("an empty run must not fabricate a request fingerprint")
	}
}
