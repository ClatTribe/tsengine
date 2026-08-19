package tenanteval

import (
	"strings"
	"testing"
)

// One sample is not a trend. Rendering a single run as a flat line would imply a stability nobody
// observed.
func TestTrendOf_RefusesASingleSample(t *testing.T) {
	for _, runs := range [][]Run{nil, {{Cases: 10, Passed: 8, SuiteHash: "a"}}} {
		got := TrendOf(runs)
		if got.Comparable {
			t.Fatalf("a trend was reported from %d run(s)", len(runs))
		}
		if got.Note == "" {
			t.Error("the refusal must explain itself")
		}
	}
}

// THE honesty rule. The suite grows every time a customer grades something — which is the behaviour
// we want — but 80% of ten cases and 80% of twelve are different measurements. Comparing them would
// punish or reward someone for grading more of their own estate.
func TestTrendOf_RefusesWhenTheGradedSetChanged(t *testing.T) {
	runs := []Run{
		{Cases: 10, Passed: 9, SuiteHash: "aaa"}, // 90%
		{Cases: 12, Passed: 6, SuiteHash: "bbb"}, // 50% — a scary drop that means nothing
	}
	got := TrendOf(runs)
	if got.Comparable || got.DeltaPoints != 0 {
		t.Fatalf("scores over different case sets were compared: %+v", got)
	}
	if !strings.Contains(got.Note, "not compared") {
		t.Errorf("the note must say the runs were not compared, got %q", got.Note)
	}
	// It must not read as a malfunction — a growing suite is the healthy case.
	if !strings.Contains(got.Note, "normal") {
		t.Errorf("a growing suite is expected and the note should say so, got %q", got.Note)
	}
}

// When the set really is identical, a regression must be reported plainly — this is the claim no
// public benchmark can make, so it has to be unambiguous when it is earned.
func TestTrendOf_ReportsARealRegressionOnAnIdenticalSuite(t *testing.T) {
	runs := []Run{
		{Cases: 10, Passed: 9, SuiteHash: "same"}, // 90%
		{Cases: 10, Passed: 7, SuiteHash: "same"}, // 70%
	}
	got := TrendOf(runs)
	if !got.Comparable {
		t.Fatal("an identical suite must be comparable")
	}
	if got.Direction != "regressed" || got.DeltaPoints != -20 {
		t.Errorf("want a 20-point regression, got %+v", got)
	}
	if !strings.Contains(got.Note, "FELL") {
		t.Errorf("a regression should be stated plainly, got %q", got.Note)
	}

	up := TrendOf([]Run{{Cases: 10, Passed: 7, SuiteHash: "same"}, {Cases: 10, Passed: 9, SuiteHash: "same"}})
	if up.Direction != "improved" || up.DeltaPoints != 20 {
		t.Errorf("want a 20-point improvement, got %+v", up)
	}
}

// The hash must change when a human REVERSES a judgement, even though the case membership is
// identical — the suite has materially changed and the runs are no longer comparable.
func TestSuiteHash_ChangesWhenAnExpectationFlips(t *testing.T) {
	a := []Case{{FindingID: "f1", Expect: Keep}, {FindingID: "f2", Expect: Suppress}}
	b := []Case{{FindingID: "f2", Expect: Suppress}, {FindingID: "f1", Expect: Keep}} // reordered only
	if SuiteHash(a) != SuiteHash(b) {
		t.Error("hash must be order-independent — the same graded set is the same set")
	}
	flipped := []Case{{FindingID: "f1", Expect: Suppress}, {FindingID: "f2", Expect: Suppress}}
	if SuiteHash(a) == SuiteHash(flipped) {
		t.Error("hash must change when an expectation flips — a reversed judgement is a different suite")
	}
	grown := append(append([]Case{}, a...), Case{FindingID: "f3", Expect: Keep})
	if SuiteHash(a) == SuiteHash(grown) {
		t.Error("hash must change when the suite grows")
	}
}
