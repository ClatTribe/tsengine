package improveloop

import (
	"fmt"
	"sort"
)

// driver.go sequences rounds. Compare judges ONE round and Weakest names ONE target; what was
// missing was the thing that decides which round to run next, and when to stop running them.
//
// The substrate-improvement step itself is a person's or an agent's — nothing here writes code. What
// the driver owns is the DISCIPLINE around that step, which is the part done wrong by default:
//
//	the target is picked deterministically, not by preference — you work on the weakest thing
//	the seeds are held out, so a round cannot be scored on the fixtures it was tuned against
//	the loop stops on return-per-dollar rather than on enthusiasm
//	a regression ends work on that capability until it is reverted, instead of being spent past
//
// Every one of those is a rule someone bypasses under time pressure, which is exactly why it belongs
// in code rather than in a runbook.

// Round is one completed attempt: the measurement it produced and the verdict on it. A round with no
// measurement (the improver failed, or the harness could not answer) is recorded with Err set — a
// round that did not happen is not an absence, it is a thing that went wrong.
type Round struct {
	N          int         `json:"n"`
	Capability string      `json:"capability"`
	Result     Measurement `json:"result"`
	Comparison Comparison  `json:"comparison"`
	Err        string      `json:"err,omitempty"`
}

// Plan is the loop's budget and its stopping rule.
type Plan struct {
	// MinDeltaPerUSD is the floor: below it, another round is not worth buying.
	MinDeltaPerUSD float64 `json:"min_delta_per_usd"`
	// MaxRounds bounds the loop regardless of returns. 0 means no cap.
	MaxRounds int `json:"max_rounds"`
	// BudgetUSD caps total spend. 0 means no cap.
	BudgetUSD float64 `json:"budget_usd"`
	// SeedStart + HoldoutK shape the held-out seed set handed to each round.
	SeedStart int64 `json:"seed_start"`
	HoldoutK  int   `json:"holdout_k"`
}

// Decision is what to do next, and why. Target and Holdout are meaningful only when Done is false.
type Decision struct {
	Done bool `json:"done"`
	// Target is the capability to work on: the weakest one still eligible.
	Target Measurement `json:"target"`
	// Holdout are seeds disjoint from everything this capability has already been tuned against.
	Holdout []int64 `json:"holdout,omitempty"`
	// Why states the reason in the terms the reader needs — which is usually why we STOPPED.
	Why string `json:"why"`
	// Blocked names capabilities excluded from further rounds and the reason each is out. Reported
	// rather than silently skipped: a loop that quietly stops working on something is
	// indistinguishable from one that finished it (CLAUDE.md §14.2 — no silent caps).
	Blocked map[string]string `json:"blocked,omitempty"`
}

// Next decides the next round from the baseline and the rounds already run.
//
// It is a pure function of the journal so the loop can be resumed, inspected, or replayed — a driver
// holding its state in memory cannot be audited afterwards, and this is the machinery that decides
// where engineering effort goes.
func Next(baseline []Measurement, rounds []Round, p Plan) Decision {
	blocked := map[string]string{}
	latest := map[string]Measurement{}
	for _, m := range baseline {
		latest[m.Capability] = m
	}

	var spent float64
	for _, r := range rounds {
		if r.Err != "" {
			// A round that errored tells us nothing about the capability, so it does not update the
			// score — but it also must not be retried as if nothing happened.
			blocked[r.Capability] = "the last round did not complete: " + r.Err
			continue
		}
		if r.Result.CostRecorded {
			spent += r.Result.CostUSD
		}
		switch r.Comparison.Verdict {
		case Regressed:
			// Not "try again": the change is still in the tree. Spending another round on top of a
			// regression compounds it, and the next measurement would be taken against a baseline
			// nobody meant to keep.
			blocked[r.Capability] = "regressed and needs reverting first: " + r.Comparison.Why
		case Incomparable:
			// The harness is wrong, not the capability. Retrying identically reproduces it.
			blocked[r.Capability] = "the last measurement could not be compared: " + r.Comparison.Why
		case Continue, Stop:
			latest[r.Capability] = r.Result
			delete(blocked, r.Capability) // a later good round clears an earlier block
			if r.Comparison.Verdict == Stop {
				blocked[r.Capability] = fmt.Sprintf(
					"returns fell below the floor (%.4f per $ < %.4f)", r.Comparison.DeltaPerUSD, p.MinDeltaPerUSD)
			}
		}
	}

	if p.MaxRounds > 0 && len(rounds) >= p.MaxRounds {
		return Decision{Done: true, Blocked: blocked, Why: fmt.Sprintf(
			"reached the %d-round cap. This is a BOUND, not a conclusion — the capabilities below "+
				"were not judged not-worth-improving, they were not reached.", p.MaxRounds)}
	}
	if p.BudgetUSD > 0 && spent >= p.BudgetUSD {
		return Decision{Done: true, Blocked: blocked, Why: fmt.Sprintf(
			"spent $%.2f of a $%.2f budget. A bound, not a conclusion.", spent, p.BudgetUSD)}
	}

	// Eligible = everything not blocked. Weakest picks among them, so the loop always works on the
	// worst thing it is still allowed to touch rather than the thing most recently discussed.
	var eligible []Measurement
	for cap, m := range latest {
		if _, out := blocked[cap]; out {
			continue
		}
		eligible = append(eligible, m)
	}
	if len(eligible) == 0 {
		why := "every capability is blocked or has stopped paying for itself"
		if len(blocked) == 0 {
			why = "no capabilities were supplied, so there is nothing to improve — an empty baseline " +
				"is not a finished one"
		}
		return Decision{Done: true, Blocked: blocked, Why: why}
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].Capability < eligible[j].Capability })

	target, ok := Weakest(eligible)
	if !ok {
		return Decision{Done: true, Blocked: blocked, Why: "no measurable capability among the eligible set"}
	}

	// Everything this capability has been tuned against, across every round — not just the last one.
	// Holding out only against the most recent round lets round 3 reuse round 1's fixtures, which is
	// the same circularity arriving one round later.
	tuned := append([]int64(nil), target.TunedOn...)
	for _, r := range rounds {
		if r.Capability == target.Capability {
			tuned = append(tuned, r.Result.TunedOn...)
			tuned = append(tuned, r.Result.Seeds...)
		}
	}
	return Decision{
		Target:  target,
		Holdout: HoldoutSeeds(tuned, p.SeedStart, p.HoldoutK),
		Blocked: blocked,
		Why:     fmt.Sprintf("%q is the weakest eligible capability at %.3f", target.Capability, target.Score),
	}
}
