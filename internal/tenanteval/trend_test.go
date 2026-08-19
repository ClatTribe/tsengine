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

// The two graders keep separate histories. Interleaved, a trend would compare a model's score
// against the filter's and present the difference as a change over time — two different subjects
// measured once each, reported as one thing moving.
func TestRunsForArm_KeepsTheGradersApart(t *testing.T) {
	runs := []Run{
		{RanAt: "1", Cases: 4, Passed: 4, SuiteHash: "h", Arm: ArmSubstrate},
		{RanAt: "2", Cases: 4, Passed: 1, SuiteHash: "h", Arm: ArmModel, Model: "m"},
		{RanAt: "3", Cases: 4, Passed: 4, SuiteHash: "h", Arm: ArmSubstrate},
	}
	if got := RunsForArm(runs, ArmSubstrate); len(got) != 2 {
		t.Fatalf("substrate history has %d run(s), want 2", len(got))
	}
	if tr := TrendOf(RunsForArm(runs, ArmSubstrate)); tr.Direction != "unchanged" {
		t.Errorf("the filter did not change, but its trend says %q — a model run leaked in", tr.Direction)
	}
	if got := RunsForArm(runs, ArmModel); len(got) != 1 {
		t.Fatalf("model history has %d run(s), want 1", len(got))
	}
}

// Runs recorded before the arm field existed were all substrate runs. Defaulting the other way
// would silently reclassify a customer's entire history as model scores.
func TestNormalizeArm_UnsetIsSubstrate(t *testing.T) {
	if NormalizeArm("") != ArmSubstrate {
		t.Fatal("an unset arm was not treated as substrate")
	}
	runs := []Run{{RanAt: "1", Cases: 2, Passed: 2, SuiteHash: "h"}}
	if len(RunsForArm(runs, ArmSubstrate)) != 1 {
		t.Error("a pre-existing run vanished from the substrate history")
	}
}

// A lower score after switching models is a reason to reconsider the switch, not a fault. Calling
// it a regression without naming the swap sends someone hunting a problem that is a decision they
// made.
func TestTrendOf_ModelSwapIsNotReportedAsAFault(t *testing.T) {
	tr := TrendOf([]Run{
		{RanAt: "1", Cases: 10, Passed: 9, SuiteHash: "h", Arm: ArmModel, Model: "anthropic/claude"},
		{RanAt: "2", Cases: 10, Passed: 5, SuiteHash: "h", Arm: ArmModel, Model: "gemini/flash"},
	})
	if !tr.ModelChanged {
		t.Fatal("the model changed between runs and the trend did not notice")
	}
	if tr.PreviousModel != "anthropic/claude" {
		t.Errorf("previous model not carried: %q", tr.PreviousModel)
	}
	if !strings.Contains(tr.Note, "different model") {
		t.Errorf("note does not say the model changed: %q", tr.Note)
	}
	if strings.Contains(tr.Note, "FELL") {
		t.Errorf("a model swap was reported in the same words as a genuine regression: %q", tr.Note)
	}
	// The delta is still real and still shown — hiding it would be its own dishonesty.
	if tr.DeltaPoints >= 0 {
		t.Errorf("the drop was not reported at all: %+v", tr)
	}
}

// The same model scoring lower IS a genuine regression, and must still say so plainly.
func TestTrendOf_SameModelScoringLowerIsStillARegression(t *testing.T) {
	tr := TrendOf([]Run{
		{RanAt: "1", Cases: 10, Passed: 9, SuiteHash: "h", Arm: ArmModel, Model: "gemini/flash"},
		{RanAt: "2", Cases: 10, Passed: 5, SuiteHash: "h", Arm: ArmModel, Model: "gemini/flash"},
	})
	if tr.ModelChanged {
		t.Fatal("reported a model change where the model is identical")
	}
	if tr.Direction != "regressed" || !strings.Contains(tr.Note, "FELL") {
		t.Errorf("a real regression was softened: %+v", tr)
	}
}
