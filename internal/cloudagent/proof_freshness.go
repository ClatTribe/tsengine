package cloudagent

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// proof_freshness.go makes a provider proof state WHEN and AGAINST WHAT it was obtained, and whether
// it still stands — ADR 0024 P1c / C4.
//
// THE PROBLEM. A policy-simulator ALLOW is a point-in-time answer about one tuple. IAM policies,
// trust documents, SCPs, permission boundaries and OIDC conditions all change, often daily and often
// by someone who has never heard of us. Rendered as a bare "provider-confirmed", a proof obtained
// three weeks ago against an account that has since been re-scoped is indistinguishable from one
// obtained a minute ago — and it is the STRONGEST claim the cloud engineer makes, so it is the worst
// one to let go quietly stale.
//
// TWO KINDS OF STALENESS, AND THEY ARE NOT THE SAME CLAIM.
//
//	DRIFT: the account's inventory hash has changed since the proof was taken. This is a FACT about
//	       the world — something we can point at. It invalidates the proof outright: the graph the
//	       tuple was evaluated against no longer exists.
//	AGE:   nothing observed has changed, but we have not re-read the account either. This is an
//	       admission about US, not a fact about the estate, so it downgrades the proof to "unverified
//	       since" rather than declaring it wrong.
//
// Collapsing them would be wrong in both directions: treating age as invalidation throws away good
// evidence on a quiet estate, and treating drift as mere age keeps asserting a proof about a graph
// that has been replaced.
//
// WHAT THE HASHES ARE FOR. SnapshotHash pins the inventory the tuple was evaluated against, so a
// later reader can re-run the same question against the same state (the §10 reproducibility base,
// cloudgraph.Snapshot.Hash). ContextHash pins the REQUEST — every tuple actually asked — because two
// runs that probed different moves are not the same proof even when both say "confirmed", and a
// proof whose request set cannot be identified cannot be re-checked at all.

// ProofFreshness is the provenance stamped on a run's probe coverage.
type ProofFreshness struct {
	// SnapshotHash is cloudgraph.Snapshot.Hash() for the inventory these probes were evaluated
	// against. Empty when the run had no snapshot, which is itself reported rather than hidden.
	SnapshotHash string `json:"snapshot_hash,omitempty"`
	// ContextHash identifies the exact set of tuples asked, so two runs are comparable and a single
	// run is re-runnable.
	ContextHash string `json:"context_hash,omitempty"`
	// ObtainedAt is the provider-result time — the earliest probe in the run, because a proof is only
	// as fresh as its oldest supporting answer.
	ObtainedAt string `json:"obtained_at,omitempty"`
}

// DefaultProofMaxAge is how long a provider proof stands before it is reported as unverified-since.
//
// Twenty-four hours is chosen to match the cadence at which the rest of the platform re-reads world
// state (the corpus refresher's default), not because IAM changes on a daily clock. It is a
// reporting threshold, never a correctness one: nothing is deleted when it passes, the proof is
// simply described as un-rechecked.
const DefaultProofMaxAge = 24 * time.Hour

// Standing is what a proof is worth right now.
type Standing string

const (
	// StandingCurrent — the snapshot is unchanged and the proof is within DefaultProofMaxAge.
	StandingCurrent Standing = "current"
	// StandingUnverifiedSince — nothing observed has changed, but we have not re-asked.
	StandingUnverifiedSince Standing = "unverified_since"
	// StandingInvalidated — the inventory changed underneath the proof.
	StandingInvalidated Standing = "invalidated_by_drift"
	// StandingUnknown — we cannot tell, because the proof carries no provenance to compare.
	StandingUnknown Standing = "unknown"
)

// Evaluate reports whether this proof still stands against the CURRENT inventory hash.
//
// currentSnapshotHash is the hash of the estate as it is now; pass "" when it is not known, which
// yields StandingUnknown rather than a verdict — not knowing whether the ground moved is a different
// statement from knowing it did not, and this is precisely the distinction the rest of the codebase
// spends its guards preserving.
func (f ProofFreshness) Evaluate(currentSnapshotHash string, now time.Time, maxAge time.Duration) (Standing, string) {
	if maxAge <= 0 {
		maxAge = DefaultProofMaxAge
	}
	if f.SnapshotHash == "" || f.ObtainedAt == "" {
		return StandingUnknown, "this proof carries no snapshot or timestamp, so whether it still holds cannot be determined"
	}
	if currentSnapshotHash == "" {
		return StandingUnknown, "the current state of the account is unknown, so whether this proof still holds cannot be determined"
	}
	if currentSnapshotHash != f.SnapshotHash {
		return StandingInvalidated, "the account's inventory has changed since this was proven (" +
			shortHash(f.SnapshotHash) + " → " + shortHash(currentSnapshotHash) + "); the graph these " +
			"permissions were evaluated against no longer exists, so the proof must be re-obtained"
	}
	obtained, err := time.Parse(time.RFC3339, f.ObtainedAt)
	if err != nil {
		return StandingUnknown, "the proof's timestamp (" + f.ObtainedAt + ") could not be read, so its age is unknown"
	}
	if age := now.Sub(obtained); age > maxAge {
		return StandingUnverifiedSince, "nothing in the account has changed, but this has not been " +
			"re-checked with the provider since " + f.ObtainedAt + " — unchanged is not the same as re-confirmed"
	}
	return StandingCurrent, "proven against the account as it stands now, at " + f.ObtainedAt
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// contextHashOf fingerprints the exact set of tuples asked. Sorted first, because two runs that asked
// the same questions in a different order are the same request and must hash alike; the answers are
// deliberately NOT included, so the hash identifies the QUESTION and a re-run can be compared against
// it rather than being trivially different for having got a different answer.
func contextHashOf(records []ProbeRecord) string {
	if len(records) == 0 {
		return ""
	}
	tuples := make([]string, 0, len(records))
	for _, r := range records {
		tuples = append(tuples, r.Principal+"\x00"+r.Action+"\x00"+r.Resource)
	}
	sort.Strings(tuples)
	sum := sha256.Sum256([]byte(strings.Join(tuples, "\x1e")))
	return hex.EncodeToString(sum[:])
}

// earliestProbedAt is the run's effective proof time: a set of answers is only as fresh as its oldest
// member. Taking the newest would let one late probe make a stale batch look current.
func earliestProbedAt(records []ProbeRecord) string {
	var best time.Time
	var bestRaw string
	for _, r := range records {
		if r.ProbedAt == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, r.ProbedAt)
		if err != nil {
			continue
		}
		if bestRaw == "" || t.Before(best) {
			best, bestRaw = t, r.ProbedAt
		}
	}
	return bestRaw
}
