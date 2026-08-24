package estategraph

import (
	"errors"
	"time"
)

// proof.go — ADR 0026 phase 1: how well an edge is PROVEN, which is a different question from
// Edge.Evidence.
//
// Evidence answers WHO ASSERTED THIS HOP EXISTS. It is required, and AddEdge refuses without it.
// It does NOT answer whether anyone ever traversed the hop — so before this file, a hop a trust
// policy merely PERMITS and a hop the pentester ACTUALLY CROSSED were the same row, to both agents
// and to the human reading the attack-path page.
//
// That distinction is the AEV lane's own definition (evidence of the FEASIBILITY of an attack), and
// this codebase already draws it one layer down: cloudgraph.PruneUnreachable separates theoretical
// network reach from real, and the provider dry-run separates config-possible from
// provider-confirmed. The graph the agents traverse was the one place it was never drawn.
//
// WHAT THIS FILE DOES NOT DO. It does not decide which findings prove which hops — that converter is
// phase 2 and lives in estateingest, so this package stays a leaf that knows about no detector.

// EdgeProof is how well an edge is proven.
//
// Each state carries a claim AND a refusal, and the refusals are the point:
//
//	ProofConfigPossible — the configuration permits this hop.
//	                      NOT a claim that anyone ever did it.
//	ProofDemonstrated   — an authorized attempt actually crossed this boundary.
//	                      NOT a claim that it is still possible today; see Edge.ProofAt.
//	ProofExploitFailed  — a recorded exploit for this hop no longer succeeds.
//	                      NOT a claim that the hop is CLOSED.
//
// There is deliberately no "closed" state. One exploit failing is not proof a hop is gone — the
// signature moved, the route moved, the payload stopped matching. Those are the cases
// platform.DisagreeScannerSeesVariant exists to name, and retest's rule is already that absence is
// the weaker evidence. An edge disappears when its CONFIG evidence disappears, which is a different
// detector's job, not a proof state.
type EdgeProof string

const (
	// ProofConfigPossible is the default. An edge added without a proof state normalises to it, so
	// every producer that predates this file keeps claiming exactly what it claimed before.
	ProofConfigPossible EdgeProof = "config_possible"
	ProofDemonstrated   EdgeProof = "demonstrated"
	ProofExploitFailed  EdgeProof = "exploit_failed"
)

// Evidenced reports whether a state rests on a recorded attempt rather than on configuration.
func (p EdgeProof) Evidenced() bool {
	return p == ProofDemonstrated || p == ProofExploitFailed
}

var (
	// ErrProofUngrounded: a proof state that cites no attempt is not a proof. Same shape as
	// ErrNoEvidence one level up — a claim nobody can replay must not enter the graph.
	ErrProofUngrounded = errors.New("estategraph: refusing a proof state with no ProofRefs — a proof nobody can replay is not a proof")
	// ErrProofUnstamped: "we have not re-checked" and "it no longer works" are different claims, and
	// only a timestamp separates them. An undated proof cannot be aged by a reader, and it cannot be
	// ordered against a later contradicting attempt — which is exactly how an old failure would come
	// to erase a new demonstration.
	ErrProofUnstamped = errors.New("estategraph: refusing an undated proof state — set ProofAt")
	// ErrUnknownProof guards the enum. A state nobody defined is not a weaker claim, it is an
	// unreadable one.
	ErrUnknownProof = errors.New("estategraph: unknown proof state")
)

// normProof maps the zero value onto the default claim. Done at AddEdge, so the encoded edge always
// carries an EXPLICIT state: a reader must never have to interpret an absent field, which is the
// silent-signal shape this repo keeps finding.
func normProof(p EdgeProof) EdgeProof {
	if p == "" {
		return ProofConfigPossible
	}
	return p
}

// MergeProof decides which of two proof claims about the SAME hop survives, and returns it with its
// timestamp.
//
// THE RULE IS TIME, NOT SEVERITY:
//
//   - A config-possible claim NEVER overrides an evidenced one. Re-ingesting an inventory is not news
//     about whether anyone crossed the hop, and letting it win would silently erase a proof — the
//     "rises on evidence, never falls silently" refusal, which is MergeSensitivity's rule applied to a
//     harder fact.
//   - An evidenced claim always beats config-possible.
//   - Between two evidenced claims the LATER one wins. On an exact tie ProofExploitFailed wins,
//     because on identical evidence the weaker claim is the honest one.
//
// WHY A RANK WOULD BE WRONG, and this is the whole reason the function exists rather than a
// comparison: a total order forces one of two bugs. Rank demonstrated highest and a fix can never be
// recorded — the demonstration outlives the thing that made it true. Rank exploit_failed highest and
// a stale failure erases a fresh crossing, telling a customer a live path is dead. Neither claim is
// intrinsically stronger; the newer attempt is.
func MergeProof(cur EdgeProof, curAt time.Time, in EdgeProof, inAt time.Time) (EdgeProof, time.Time) {
	cur, in = normProof(cur), normProof(in)
	switch {
	case !in.Evidenced():
		return cur, curAt
	case !cur.Evidenced():
		return in, inAt
	case inAt.After(curAt):
		return in, inAt
	case curAt.After(inAt):
		return cur, curAt
	case cur == ProofExploitFailed || in == ProofExploitFailed:
		return ProofExploitFailed, curAt
	default:
		return cur, curAt
	}
}

// Proof reports the path's proof state: its WEAKEST hop.
//
// A path is demonstrated only if EVERY hop is. Calling a path proven because one hop was is the
// overclaim this whole mechanism exists to remove.
//
// The interesting refusal is the other end. A path carrying an untested hop reports
// ProofConfigPossible even when another hop's exploit has failed — because ProofExploitFailed on a
// PATH reads as "we ran this route and it stopped working", which implies the route once worked. Only
// a path whose every hop is evidenced has earned that sentence.
func (p Path) Proof() EdgeProof {
	if len(p.Edges) == 0 {
		return ProofConfigPossible
	}
	worst := ProofDemonstrated
	for _, e := range p.Edges {
		switch normProof(e.Proof) {
		case ProofConfigPossible:
			return ProofConfigPossible
		case ProofExploitFailed:
			worst = ProofExploitFailed
		}
	}
	return worst
}
