// Package improveloop is the cost discipline on ADR 0018's simulation loop: it decides
// when to keep spending on improvement and when to stop, and it refuses to compare two
// measurements that cannot honestly be compared.
//
// The loop the ADR describes is measure → find the weakest capability → generate seeded
// scenarios targeting it → improve the substrate → re-measure on HELD-OUT seeds → stop
// when Δbenchmark per dollar falls below a threshold. The improvement step is a person's
// or an agent's; everything around it is arithmetic, and the arithmetic is where the
// dishonest version lives.
//
// TWO FAILURES THIS EXISTS TO MAKE STRUCTURALLY IMPOSSIBLE:
//
//  1. CIRCULARITY. Tuning against one seed range and scoring against the same one measures
//     how well the change fits the seeds it was written against. It is the exact
//     circularity holdout.go was built to escape, it is trivially easy to do by accident
//     because the generator is right there, and the result looks like progress. Compare
//     REFUSES when the tuning seeds and the scoring seeds overlap.
//
//  2. UNBOUNDED EXPLORATION. Without a stopping rule the loop runs until someone gets
//     bored, and the last dollars buy the least. The ADR's rule is Δ per dollar, and it
//     needs a floor to compare against — otherwise "it went up a bit" always argues for
//     one more round.
package improveloop

import (
	"errors"
	"fmt"
	"sort"
)

// Measurement is one capability's score on one run, with what the run cost.
type Measurement struct {
	// Capability is the thing being measured (a bench name, a per-class recall).
	Capability string `json:"capability"`
	// Score is on [0,1]. Higher is better; comparisons assume that direction.
	Score float64 `json:"score"`
	// Seeds are the generator seeds this score was computed over. Load-bearing: it is
	// what lets Compare detect that a change was tuned and scored on the same fixtures.
	Seeds []int64 `json:"seeds,omitempty"`
	// TunedOn are the seeds the change under test was DEVELOPED against, when known. A
	// run that reports none is treated as "we were not told", not as "none" — see
	// Compare.
	TunedOn []int64 `json:"tuned_on,omitempty"`
	// CostUSD is what producing this measurement cost. Zero means free (a deterministic
	// bench) or unrecorded, and Compare distinguishes those two cases from each other.
	CostUSD float64 `json:"cost_usd"`
	// CostRecorded separates "this was free" from "nobody wrote the cost down". Dividing
	// by an unrecorded zero would report infinite efficiency for a run whose spend simply
	// was not measured.
	CostRecorded bool `json:"cost_recorded"`
	// DecoyPassed reports whether the grounding control held. It is a GATE, not a metric:
	// a change that raises the score while confirming a decoy traded grounding for a
	// number, and that is a regression however the score moved.
	DecoyPassed bool `json:"decoy_passed"`
}

// Verdict is what to do next.
type Verdict string

const (
	// Continue: the last round bought enough to justify another.
	Continue Verdict = "continue"
	// Stop: the return per dollar has fallen below the floor. Not a failure — it is the
	// loop working.
	Stop Verdict = "stop"
	// Regressed: the score fell, or the decoy gate broke. Either way the change should
	// come out, and neither is a reason to spend more.
	Regressed Verdict = "regressed"
	// Incomparable: the two measurements cannot honestly be compared. Reported as itself
	// rather than resolved to one of the above, because a wrong comparison is worse than
	// no comparison and both alternatives would hide it.
	Incomparable Verdict = "incomparable"
)

// Comparison is the result of weighing one round against the previous one.
type Comparison struct {
	Capability string  `json:"capability"`
	Before     float64 `json:"before"`
	After      float64 `json:"after"`
	Delta      float64 `json:"delta"`
	CostUSD    float64 `json:"cost_usd"`
	// DeltaPerUSD is reported only when HasRate is true — a score change with no recorded
	// spend has no rate, and a sentinel would make the cheapest-looking round the one
	// nobody costed.
	DeltaPerUSD float64 `json:"delta_per_usd,omitempty"`
	HasRate     bool    `json:"has_rate"`
	Verdict     Verdict `json:"verdict"`
	// Why states the reason in the terms the caller needs to act on.
	Why string `json:"why"`
}

// ErrSeedOverlap is returned when a change was tuned on seeds it is also scored against.
var ErrSeedOverlap = errors.New("improveloop: tuned and scored on overlapping seeds")

// Compare weighs an after-measurement against a before-measurement.
//
// minDeltaPerUSD is the floor: below it, another round is not worth buying. Pass 0 to
// disable the economic gate and judge on direction alone.
func Compare(before, after Measurement, minDeltaPerUSD float64) (Comparison, error) {
	c := Comparison{
		Capability: after.Capability,
		Before:     before.Score,
		After:      after.Score,
		Delta:      after.Score - before.Score,
		CostUSD:    after.CostUSD,
	}
	if before.Capability != after.Capability {
		c.Verdict, c.Why = Incomparable, fmt.Sprintf(
			"different capabilities (%q then %q) — a delta across them measures nothing",
			before.Capability, after.Capability)
		return c, nil
	}
	// The circularity check, before anything else: a number produced this way should not
	// be reported at all, not reported with a caveat.
	if overlap := intersect(after.TunedOn, after.Seeds); len(overlap) > 0 {
		c.Verdict = Incomparable
		c.Why = fmt.Sprintf("scored on %d seed(s) the change was tuned against (%v) — this measures "+
			"how well the change fits its own fixtures, which is the circularity held-out seeds exist "+
			"to escape", len(overlap), overlap)
		return c, ErrSeedOverlap
	}
	// The grounding gate outranks the score. A change that confirms a decoy traded
	// grounding for a number.
	if !after.DecoyPassed {
		c.Verdict, c.Why = Regressed, "the decoy control failed — the change confirmed something "+
			"planted to be inert, so any score gain was bought with grounding"
		return c, nil
	}
	if c.Delta < 0 {
		c.Verdict, c.Why = Regressed, fmt.Sprintf("the score fell %.3f", -c.Delta)
		return c, nil
	}
	if after.CostRecorded && after.CostUSD > 0 {
		c.DeltaPerUSD, c.HasRate = c.Delta/after.CostUSD, true
	}
	switch {
	case !c.HasRate && minDeltaPerUSD > 0:
		// The caller asked for an economic decision and gave nothing to make it with.
		c.Verdict = Incomparable
		c.Why = "no recorded cost, so there is no return per dollar to compare against the floor — " +
			"record the spend or drop the floor, but do not read this as cheap"
	case c.Delta == 0:
		c.Verdict, c.Why = Stop, "the score did not move; another identical round will not move it either"
	case c.HasRate && c.DeltaPerUSD < minDeltaPerUSD:
		c.Verdict = Stop
		c.Why = fmt.Sprintf("gained %.3f for $%.2f (%.4f per dollar), below the %.4f floor",
			c.Delta, c.CostUSD, c.DeltaPerUSD, minDeltaPerUSD)
	default:
		c.Verdict = Continue
		if c.HasRate {
			c.Why = fmt.Sprintf("gained %.3f for $%.2f (%.4f per dollar)", c.Delta, c.CostUSD, c.DeltaPerUSD)
		} else {
			c.Why = fmt.Sprintf("gained %.3f (cost not recorded, so judged on direction alone)", c.Delta)
		}
	}
	return c, nil
}

// Weakest names the capability to target next: the lowest score in the set.
//
// Ties break on the capability name so a run is deterministic — an improvement loop that
// picks a different target on identical input cannot be reasoned about across rounds.
// Returns ok=false for an empty set rather than a zero-valued Measurement, since "nothing
// measured" and "everything scores zero" are opposite situations.
func Weakest(ms []Measurement) (Measurement, bool) {
	if len(ms) == 0 {
		return Measurement{}, false
	}
	sorted := append([]Measurement{}, ms...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score == sorted[j].Score {
			return sorted[i].Capability < sorted[j].Capability
		}
		return sorted[i].Score < sorted[j].Score
	})
	return sorted[0], true
}

// HoldoutSeeds returns k seeds guaranteed disjoint from tunedOn, so a caller cannot
// accidentally score against the fixtures it developed on.
//
// It walks forward from start rather than drawing randomly: the loop must be reproducible
// across rounds, and a random holdout that happens to collide is precisely the failure the
// disjointness is for.
func HoldoutSeeds(tunedOn []int64, start int64, k int) []int64 {
	if k <= 0 {
		return nil
	}
	used := map[int64]bool{}
	for _, s := range tunedOn {
		used[s] = true
	}
	out := make([]int64, 0, k)
	for s := start; len(out) < k; s++ {
		if !used[s] {
			out = append(out, s)
		}
	}
	return out
}

func intersect(a, b []int64) []int64 {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	in := map[int64]bool{}
	for _, x := range a {
		in[x] = true
	}
	var out []int64
	seen := map[int64]bool{}
	for _, y := range b {
		if in[y] && !seen[y] {
			seen[y] = true
			out = append(out, y)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
