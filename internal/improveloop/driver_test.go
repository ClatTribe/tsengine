package improveloop

import (
	"strings"
	"testing"
)

func meas(cap string, score float64, opts ...func(*Measurement)) Measurement {
	x := Measurement{Capability: cap, Score: score, DecoyPassed: true}
	for _, o := range opts {
		o(&x)
	}
	return x
}
func withCost(u float64) func(*Measurement) {
	return func(x *Measurement) { x.CostUSD, x.CostRecorded = u, true }
}
func withSeeds(s ...int64) func(*Measurement) { return func(x *Measurement) { x.Seeds = s } }
func withTuned(s ...int64) func(*Measurement) { return func(x *Measurement) { x.TunedOn = s } }

var plan = Plan{MinDeltaPerUSD: 0.01, MaxRounds: 10, SeedStart: 1000, HoldoutK: 3}

// The target is picked by the numbers, not by preference. Working on the thing most recently
// discussed is how a loop spends a quarter on something already at 0.97.
func TestNext_PicksTheWeakestCapability(t *testing.T) {
	d := Next([]Measurement{meas("sast", 0.46), meas("sca", 0.99), meas("dast", 0.12)}, nil, plan)
	if d.Done {
		t.Fatal("there is work to do")
	}
	if d.Target.Capability != "dast" {
		t.Errorf("target = %q, want the weakest (dast at 0.12)", d.Target.Capability)
	}
}

// A regression BLOCKS its capability rather than triggering a retry. The change is still in the tree:
// another round on top of it compounds the regression, and the next measurement would be taken
// against a baseline nobody meant to keep.
func TestNext_ARegressionBlocksThatCapabilityUntilReverted(t *testing.T) {
	rounds := []Round{{
		N: 1, Capability: "dast", Result: meas("dast", 0.08, withCost(5)),
		Comparison: Comparison{Capability: "dast", Verdict: Regressed, Why: "the score fell 0.040"},
	}}
	d := Next([]Measurement{meas("dast", 0.12), meas("sast", 0.46)}, rounds, plan)
	if d.Target.Capability == "dast" {
		t.Error("a regressed capability must not be worked on again before it is reverted")
	}
	if !strings.Contains(d.Blocked["dast"], "revert") {
		t.Errorf("the block must say what to do about it, got %q", d.Blocked["dast"])
	}
	if d.Target.Capability != "sast" {
		t.Errorf("the loop should move to the next eligible capability, got %q", d.Target.Capability)
	}
}

// Incomparable is the HARNESS being wrong, not the capability being bad. Retrying it identically
// reproduces it, so it blocks too — and it must not be silently reported as a regression.
func TestNext_IncomparableBlocksAndSaysSo(t *testing.T) {
	rounds := []Round{{
		N: 1, Capability: "dast", Result: meas("dast", 0.30),
		Comparison: Comparison{Capability: "dast", Verdict: Incomparable, Why: "scored on 2 seed(s) the change was tuned against"},
	}}
	d := Next([]Measurement{meas("dast", 0.12)}, rounds, plan)
	if !d.Done {
		t.Fatal("nothing else is eligible")
	}
	if !strings.Contains(d.Blocked["dast"], "could not be compared") {
		t.Errorf("want the harness reason, got %q", d.Blocked["dast"])
	}
}

// Held-out seeds must be disjoint from EVERY round's fixtures for that capability, not just the last.
// Holding out against only the most recent round lets round 3 reuse round 1's seeds — the same
// circularity, arriving a round later.
func TestNext_HoldsOutAgainstEveryPreviousRoundNotJustTheLast(t *testing.T) {
	// Seeds and TunedOn are DELIBERATELY different here. Setting them to the same values makes this
	// test unfalsifiable — dropping the seeds from the exclusion changes nothing, because TunedOn
	// already covers them. That was the first version, and the mutation that should have turned it
	// red did not.
	//
	// A seed already SCORED ON is not reusable either, and for the weaker but real reason: whoever
	// made the next change saw how the last one did on it, so a re-score is partly a memory of that
	// result rather than a fresh measurement.
	rounds := []Round{
		// The scored-on seeds sit exactly where HoldoutSeeds would otherwise draw from (SeedStart
		// upward). Putting them out of that range — 2000+ against a start of 1000 — makes the test pass
		// whether or not they are excluded, which is how the first TWO versions of this fixture managed
		// to assert nothing.
		{N: 1, Capability: "dast", Result: meas("dast", 0.20, withSeeds(1000, 1001), withTuned(9000)),
			Comparison: Comparison{Capability: "dast", Verdict: Continue}},
		{N: 2, Capability: "dast", Result: meas("dast", 0.25, withSeeds(1002), withTuned(9001)),
			Comparison: Comparison{Capability: "dast", Verdict: Continue}},
	}
	d := Next([]Measurement{meas("dast", 0.12)}, rounds, plan)
	used := map[int64]bool{1000: true, 1001: true, 1002: true, 9000: true, 9001: true}
	for _, s := range d.Holdout {
		if used[s] {
			t.Errorf("held-out seed %d was already used by an earlier round — round 1's fixtures are "+
				"just as circular in round 3 as they were in round 2, and a seed already scored on "+
				"is a result the next change was made with knowledge of", s)
		}
	}
	if len(d.Holdout) != plan.HoldoutK {
		t.Errorf("want %d held-out seeds, got %d", plan.HoldoutK, len(d.Holdout))
	}
}

// Stopping on returns is the loop WORKING. It must say which capability stopped and why, or a stop
// is indistinguishable from having run out of ideas.
func TestNext_StopIsRecordedWithItsReason(t *testing.T) {
	rounds := []Round{{
		N: 1, Capability: "sast", Result: meas("sast", 0.47, withCost(500)),
		Comparison: Comparison{Capability: "sast", Verdict: Stop, DeltaPerUSD: 0.00002, HasRate: true},
	}}
	d := Next([]Measurement{meas("sast", 0.46)}, rounds, plan)
	if !strings.Contains(d.Blocked["sast"], "floor") {
		t.Errorf("a stop must name the rule that produced it, got %q", d.Blocked["sast"])
	}
}

// A bound is not a conclusion. A loop that stops because it ran out of budget has NOT decided the
// remaining capabilities are fine, and saying so is the difference between a finished job and an
// interrupted one.
func TestNext_BoundsSayTheyAreBoundsNotConclusions(t *testing.T) {
	base := []Measurement{meas("dast", 0.12)}
	rounds := []Round{{N: 1, Capability: "dast", Result: meas("dast", 0.20, withCost(120)),
		Comparison: Comparison{Capability: "dast", Verdict: Continue}}}

	d := Next(base, rounds, Plan{MinDeltaPerUSD: 0.01, BudgetUSD: 100, SeedStart: 1, HoldoutK: 2})
	if !d.Done || !strings.Contains(d.Why, "not a conclusion") {
		t.Errorf("budget exhaustion must be stated as a bound, got done=%v why=%q", d.Done, d.Why)
	}

	d2 := Next(base, rounds, Plan{MinDeltaPerUSD: 0.01, MaxRounds: 1, SeedStart: 1, HoldoutK: 2})
	if !d2.Done || !strings.Contains(d2.Why, "not reached") {
		t.Errorf("the round cap must say the rest were not reached, got %q", d2.Why)
	}
}

// An empty baseline is not a finished loop.
func TestNext_EmptyBaselineIsNotSuccess(t *testing.T) {
	d := Next(nil, nil, plan)
	if !d.Done {
		t.Fatal("nothing to do")
	}
	if !strings.Contains(d.Why, "not a finished one") {
		t.Errorf("an empty baseline must not read as completion, got %q", d.Why)
	}
}

// A later good round clears an earlier block: the capability was reverted and re-measured, and the
// loop must be able to resume rather than treating one bad round as permanent.
func TestNext_AGoodRoundClearsAnEarlierBlock(t *testing.T) {
	rounds := []Round{
		{N: 1, Capability: "dast", Result: meas("dast", 0.08),
			Comparison: Comparison{Capability: "dast", Verdict: Regressed, Why: "fell"}},
		{N: 2, Capability: "dast", Result: meas("dast", 0.30, withCost(10)),
			Comparison: Comparison{Capability: "dast", Verdict: Continue, DeltaPerUSD: 0.02, HasRate: true}},
	}
	d := Next([]Measurement{meas("dast", 0.12)}, rounds, plan)
	if _, blocked := d.Blocked["dast"]; blocked {
		t.Error("a reverted-and-improved capability must become eligible again")
	}
	if d.Done {
		t.Error("there is still work to do on dast")
	}
}

// A round that ERRORED tells us nothing about the capability, so it must not update the score — and
// must not be retried as if it had not happened.
func TestNext_AFailedRoundDoesNotBecomeAScore(t *testing.T) {
	rounds := []Round{{N: 1, Capability: "dast", Result: meas("dast", 0.99), Err: "sandbox never became ready"}}
	d := Next([]Measurement{meas("dast", 0.12)}, rounds, plan)
	if !strings.Contains(d.Blocked["dast"], "did not complete") {
		t.Errorf("a failed round must be reported as failed, got %q", d.Blocked["dast"])
	}
	if d.Target.Capability == "dast" && d.Target.Score == 0.99 {
		t.Error("the score from a round that errored must never become the baseline")
	}
}
