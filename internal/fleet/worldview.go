// Package fleet is the engagement coordinator of ADR 0030: it decomposes an authorized surface into
// chunks, runs existing agents as workers over them, and merges each debrief into a per-engagement
// WORLDVIEW — what was tried, proven, denied, contested, or never reached.
//
// This file is the worldview state machine, the load-bearing core the whole ADR rests on. Two
// properties make it ours rather than a generic coverage map (§10):
//
//   - EVIDENCE-OR-REFUSE: Update rejects a claim carrying no evidence (ErrNoEvidence), the same
//     contract estategraph.AddEdge enforces on estate facts. A verdict nothing observed cannot enter.
//   - CONTESTED-NOT-AVERAGED: two workers disagreeing (one Clean, one Vulnerable on the same
//     route×class) produce Contested — a recorded, honest "we do not agree", never a silent
//     overwrite and never a numeric average of incompatible facts.
//
// The worldview is PER-ENGAGEMENT and its verdicts are OVERTURNABLE (a re-probe may move Clean →
// Contested). That is the opposite of estategraph, whose facts only ever rise — which is exactly why
// ADR 0030 keeps them as two types over one identity space, never merged (D1).
package fleet

import (
	"errors"
	"sort"
)

// Verdict is what an engagement established about one (route, class) pair.
type Verdict string

const (
	// Vulnerable: a worker proved the class exploitable here (a real finding).
	Vulnerable Verdict = "vulnerable"
	// Clean: the class was ATTEMPTED against this route and did not fire. Groundable only when the
	// scope of the attempt is known (a completed chunk, Phase B) — absence of a finding on a route a
	// worker merely passed through is NOT Clean (§10), it is no verdict at all.
	Clean Verdict = "clean"
	// Denied: the probe was refused by access control (401/403) — we could not test, distinct from
	// tested-and-safe. Reading Denied as Clean is the exact overclaim the ledger exists to prevent.
	Denied Verdict = "denied"
	// Inconclusive: attempted, but the signal was ambiguous (timeout, unstable response).
	Inconclusive Verdict = "inconclusive"
	// Contested: independent looks disagreed (a Vulnerable vs a Clean). Terminal under deterministic
	// merge; only the adjudication path (Phase C/D) resolves it, and never by upgrading to verified.
	Contested Verdict = "contested"
)

// precedence orders the non-Contested verdicts for the "no direct conflict" case. Higher wins.
// Vulnerable (proven) dominates; Clean (tested-safe) beats Denied (could-not-test) beats
// Inconclusive (ambiguous). The one pair that does NOT resolve by precedence is Vulnerable×Clean —
// that is a real disagreement, so it becomes Contested rather than letting "proven" quietly bury a
// "tested-safe" from an equally-grounded look.
var precedence = map[Verdict]int{
	Vulnerable:   4,
	Clean:        3,
	Denied:       2,
	Inconclusive: 1,
}

// resolve combines two verdicts. It is COMMUTATIVE and ASSOCIATIVE (the golden-merge property, so
// the same debriefs in any order yield the same worldview): Contested is absorbing, a Vulnerable
// paired with a Clean is Contested, and everything else is the higher-precedence verdict.
func resolve(a, b Verdict) Verdict {
	if a == Contested || b == Contested {
		return Contested
	}
	if (a == Vulnerable && b == Clean) || (a == Clean && b == Vulnerable) {
		return Contested
	}
	if precedence[a] >= precedence[b] {
		return a
	}
	return b
}

// Claim is one worker's assertion about a route×class, carrying the turn-IDs that back it. Route is a
// Canonical identity (estategraph.Canonical) by the time it reaches Update — the worldview stores
// projections of estate nodes, never a second universe of stringly-typed endpoints (D1).
type Claim struct {
	Route    string   `json:"route"`
	Class    string   `json:"class"`
	Verdict  Verdict  `json:"verdict"`
	Evidence []string `json:"evidence"` // turn IDs from the worker's own History
}

// ClassVerdict is the merged state for one route×class.
type ClassVerdict struct {
	Route    string   `json:"route"`
	Class    string   `json:"class"`
	Verdict  Verdict  `json:"verdict"`
	Evidence []string `json:"evidence"` // union across contributing claims, sorted (deterministic)
	Workers  int      `json:"workers"`  // independent looks that touched this route×class
}

// Worldview is the per-engagement coverage ledger, keyed by route×class.
type Worldview struct {
	verdicts map[string]ClassVerdict
}

// ErrNoEvidence is returned by Update for a claim with no backing turns — the evidence-or-refuse rule.
var ErrNoEvidence = errors.New("fleet: claim carries no evidence (a verdict nothing observed cannot enter the worldview)")

// New returns an empty worldview.
func New() *Worldview { return &Worldview{verdicts: map[string]ClassVerdict{}} }

func key(route, class string) string { return route + "\x00" + class }

// Update merges claims into the worldview. It is all-or-nothing on validation: if ANY claim lacks
// evidence it returns ErrNoEvidence and mutates nothing, so a caller never half-applies a batch. The
// merge itself is order-independent (resolve is commutative/associative), which is what
// TestMerge_OrderIndependent pins.
func (w *Worldview) Update(claims []Claim) error {
	for _, c := range claims {
		if len(nonEmpty(c.Evidence)) == 0 {
			return ErrNoEvidence
		}
		if c.Verdict == "" || c.Route == "" || c.Class == "" {
			return errors.New("fleet: claim missing route, class, or verdict")
		}
	}
	for _, c := range claims {
		k := key(c.Route, c.Class)
		cur, ok := w.verdicts[k]
		if !ok {
			w.verdicts[k] = ClassVerdict{
				Route: c.Route, Class: c.Class, Verdict: c.Verdict,
				Evidence: sortUnique(c.Evidence), Workers: 1,
			}
			continue
		}
		cur.Verdict = resolve(cur.Verdict, c.Verdict)
		cur.Evidence = sortUnique(append(cur.Evidence, c.Evidence...))
		cur.Workers++ // one more independent look touched this route×class
		w.verdicts[k] = cur
	}
	return nil
}

// Verdicts returns the ledger sorted by (route, class) — deterministic ordering for rendering and
// golden tests.
func (w *Worldview) Verdicts() []ClassVerdict {
	out := make([]ClassVerdict, 0, len(w.verdicts))
	for _, v := range w.verdicts {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// Get returns the verdict for one route×class, if established.
func (w *Worldview) Get(route, class string) (ClassVerdict, bool) {
	v, ok := w.verdicts[key(route, class)]
	return v, ok
}

// Counts tallies the ledger by verdict — the summary the report and scheduler read.
func (w *Worldview) Counts() map[Verdict]int {
	out := map[Verdict]int{}
	for _, v := range w.verdicts {
		out[v.Verdict]++
	}
	return out
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func sortUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
