package improveloop

import (
	"errors"
	"strings"
	"testing"
)

func m(cap string, score float64, cost float64, seeds, tuned []int64) Measurement {
	return Measurement{Capability: cap, Score: score, CostUSD: cost, CostRecorded: cost > 0,
		Seeds: seeds, TunedOn: tuned, DecoyPassed: true}
}

// THE CIRCULARITY. Tuning against one seed range and scoring against the same one measures
// how well the change fits the seeds it was written against. It is trivially easy to do by
// accident because the generator is right there, and the result looks exactly like
// progress — so it has to be refused rather than caveated.
func TestCompare_RefusesToScoreOnTunedSeeds(t *testing.T) {
	before := m("cloud-privesc", 0.60, 0, []int64{100, 101}, nil)
	after := m("cloud-privesc", 0.95, 4, []int64{100, 101}, []int64{99, 100})
	got, err := Compare(before, after, 0)
	if !errors.Is(err, ErrSeedOverlap) {
		t.Fatalf("want ErrSeedOverlap, got %v", err)
	}
	if got.Verdict != Incomparable {
		t.Errorf("verdict = %q, want incomparable — a 0.35 gain on its own fixtures is not a gain", got.Verdict)
	}
	if !strings.Contains(got.Why, "100") {
		t.Errorf("the reason must name the overlapping seed so it can be fixed: %q", got.Why)
	}
}

// Disjoint seeds are the normal case and must compare cleanly.
func TestCompare_DisjointSeedsCompare(t *testing.T) {
	before := m("cloud-privesc", 0.60, 0, []int64{200, 201}, nil)
	after := m("cloud-privesc", 0.80, 2, []int64{300, 301}, []int64{200, 201})
	got, err := Compare(before, after, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != Continue || got.Delta < 0.19 {
		t.Errorf("got %+v; want a clean continue on a real gain", got)
	}
	if !got.HasRate || got.DeltaPerUSD < 0.09 {
		t.Errorf("DeltaPerUSD = %v (%v), want ~0.1", got.DeltaPerUSD, got.HasRate)
	}
}

// The grounding gate OUTRANKS the score. A change that confirms a decoy bought its number
// with grounding, and that is a regression however far the score moved.
func TestCompare_DecoyFailureBeatsAScoreGain(t *testing.T) {
	before := m("cloud-privesc", 0.60, 0, []int64{200}, nil)
	after := m("cloud-privesc", 0.99, 1, []int64{300}, nil)
	after.DecoyPassed = false
	got, _ := Compare(before, after, 0)
	if got.Verdict != Regressed {
		t.Errorf("verdict = %q; a decoy confirmation is a regression even at 0.99", got.Verdict)
	}
	if !strings.Contains(got.Why, "grounding") {
		t.Errorf("the reason must say what was traded away: %q", got.Why)
	}
}

// The stopping rule: the last dollars buy the least, and without a floor "it went up a
// bit" always argues for one more round.
func TestCompare_StopsWhenTheReturnFallsBelowTheFloor(t *testing.T) {
	before := m("cloud-privesc", 0.90, 0, []int64{200}, nil)
	after := m("cloud-privesc", 0.902, 40, []int64{300}, nil) // 0.00005 per dollar
	got, _ := Compare(before, after, 0.001)
	if got.Verdict != Stop {
		t.Errorf("verdict = %q, want stop: %s", got.Verdict, got.Why)
	}
	if !strings.Contains(got.Why, "floor") {
		t.Errorf("the reason must name the floor it fell under: %q", got.Why)
	}
}

// An unrecorded cost is not a free round. Dividing by it would report infinite efficiency
// for a run whose spend simply was not written down — the cheapest-looking round would be
// the one nobody costed.
func TestCompare_UnrecordedCostIsNotCheap(t *testing.T) {
	before := m("cloud-privesc", 0.60, 0, []int64{200}, nil)
	after := Measurement{Capability: "cloud-privesc", Score: 0.80, Seeds: []int64{300}, DecoyPassed: true}
	got, _ := Compare(before, after, 0.01)
	if got.Verdict != Incomparable {
		t.Errorf("verdict = %q; an economic decision with no cost recorded cannot be made", got.Verdict)
	}
	if got.HasRate {
		t.Error("no cost means no rate")
	}
	if !strings.Contains(got.Why, "do not read this as cheap") {
		t.Errorf("the reason must block the tempting reading: %q", got.Why)
	}
}

// With the economic gate off, direction alone decides — so an uncosted deterministic bench
// still works.
func TestCompare_NoFloorJudgesOnDirection(t *testing.T) {
	before := m("sast", 0.40, 0, []int64{1}, nil)
	after := Measurement{Capability: "sast", Score: 0.55, Seeds: []int64{2}, DecoyPassed: true}
	got, _ := Compare(before, after, 0)
	if got.Verdict != Continue {
		t.Errorf("verdict = %q, want continue: %s", got.Verdict, got.Why)
	}
}

// Comparing two different capabilities measures nothing, and the shapes do not prevent it.
func TestCompare_DifferentCapabilitiesAreIncomparable(t *testing.T) {
	got, _ := Compare(m("sast", 0.4, 0, nil, nil), m("cloud-privesc", 0.9, 1, nil, nil), 0)
	if got.Verdict != Incomparable {
		t.Errorf("verdict = %q, want incomparable", got.Verdict)
	}
}

// A flat score stops: another identical round will not move it either.
func TestCompare_NoMovementStops(t *testing.T) {
	got, _ := Compare(m("sast", 0.7, 0, []int64{1}, nil), m("sast", 0.7, 3, []int64{2}, nil), 0)
	if got.Verdict != Stop {
		t.Errorf("verdict = %q, want stop: %s", got.Verdict, got.Why)
	}
}

// Weakest picks the target for the next round, deterministically — a loop that picks a
// different target on identical input cannot be reasoned about across rounds.
func TestWeakest_DeterministicAndHonestWhenEmpty(t *testing.T) {
	set := []Measurement{m("b", 0.5, 0, nil, nil), m("a", 0.5, 0, nil, nil), m("c", 0.9, 0, nil, nil)}
	for i := 0; i < 5; i++ {
		w, ok := Weakest(set)
		if !ok || w.Capability != "a" {
			t.Fatalf("Weakest = %v (%v), want the tie broken on name", w.Capability, ok)
		}
	}
	if _, ok := Weakest(nil); ok {
		t.Error("nothing measured must report ok=false, not a zero-scored capability — those are opposite situations")
	}
}

// HoldoutSeeds must be disjoint by construction. A random holdout that happens to collide
// is exactly the failure the disjointness is for.
func TestHoldoutSeeds_DisjointAndReproducible(t *testing.T) {
	tuned := []int64{10, 11, 12, 14}
	got := HoldoutSeeds(tuned, 10, 4)
	if len(got) != 4 {
		t.Fatalf("want 4 seeds, got %v", got)
	}
	for _, s := range got {
		for _, t2 := range tuned {
			if s == t2 {
				t.Errorf("seed %d overlaps the tuning set %v", s, tuned)
			}
		}
	}
	again := HoldoutSeeds(tuned, 10, 4)
	for i := range got {
		if got[i] != again[i] {
			t.Fatalf("not reproducible: %v vs %v", got, again)
		}
	}
	// And the whole point: feeding these back into Compare must not trip the overlap check.
	after := Measurement{Capability: "x", Score: 0.8, Seeds: got, TunedOn: tuned, DecoyPassed: true, CostUSD: 1, CostRecorded: true}
	if _, err := Compare(Measurement{Capability: "x", Score: 0.5, DecoyPassed: true}, after, 0); err != nil {
		t.Errorf("holdout seeds must be safe to score on: %v", err)
	}
}
