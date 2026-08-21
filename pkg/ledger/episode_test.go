package ledger

import (
	"errors"
	"testing"
	"time"
)

func st(scope string, keys []string, sev map[string]int, facts map[string]int) *SecurityState {
	return &SecurityState{At: time.Unix(0, 0).UTC(), Scope: scope, IssueKeys: keys, BySeverity: sev, Facts: facts}
}

// The refusal that stops a delta from being a fabrication. Nothing about the two shapes
// prevents diffing a repository census against a cloud one — and the result would report
// every repo issue closed and every cloud issue opened, which reads as spectacular
// progress and is pure noise.
func TestDiff_RefusesDifferentScopes(t *testing.T) {
	_, err := Diff(st("repo:acme/api", []string{"a", "b"}, nil, nil),
		st("aws:123456789012", []string{"c"}, nil, nil))
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("want ErrScopeMismatch, got %v", err)
	}
}

// "We did not look" and "there was nothing" are different claims. Treating an absent
// before-state as empty would make the first episode on every target report that the
// agent OPENED every issue it merely found.
func TestDiff_RefusesAHalfBracket(t *testing.T) {
	if _, err := Diff(nil, st("s", []string{"a"}, nil, nil)); err == nil {
		t.Error("a delta from one snapshot must be refused, not assumed empty")
	}
	if _, err := Diff(st("s", []string{"a"}, nil, nil), nil); err == nil {
		t.Error("a missing after-state must be refused")
	}
}

func TestDiff_OpenedClosedPersisted(t *testing.T) {
	before := st("s", []string{"keep", "gone"}, map[string]int{"high": 2}, map[string]int{"privesc_edges": 3})
	after := st("s", []string{"keep", "new"}, map[string]int{"high": 1, "low": 1}, map[string]int{"privesc_edges": 1})
	d, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Opened) != 1 || d.Opened[0] != "new" {
		t.Errorf("Opened = %v, want [new]", d.Opened)
	}
	if len(d.Closed) != 1 || d.Closed[0] != "gone" {
		t.Errorf("Closed = %v, want [gone]", d.Closed)
	}
	if d.Persisted != 1 {
		t.Errorf("Persisted = %d, want 1", d.Persisted)
	}
	if d.SeverityDelta["high"] != -1 || d.SeverityDelta["low"] != 1 {
		t.Errorf("SeverityDelta = %v", d.SeverityDelta)
	}
	if d.FactDelta["privesc_edges"] != -2 {
		t.Errorf("FactDelta = %v, want privesc_edges:-2", d.FactDelta)
	}
}

// An unchanged count is not a change and must not be reported as one — otherwise every
// delta carries a wall of zeros and the real movements stop standing out.
func TestDiff_UnchangedCountsAreNotReported(t *testing.T) {
	same := map[string]int{"high": 2, "low": 1}
	d, err := Diff(st("s", []string{"a"}, same, same), st("s", []string{"a"}, same, same))
	if err != nil {
		t.Fatal(err)
	}
	if d.SeverityDelta != nil || d.FactDelta != nil {
		t.Errorf("want no deltas for an unchanged posture, got sev=%v facts=%v", d.SeverityDelta, d.FactDelta)
	}
	if d.Persisted != 1 || len(d.Opened) != 0 || len(d.Closed) != 0 {
		t.Errorf("unchanged posture: persisted=%d opened=%v closed=%v", d.Persisted, d.Opened, d.Closed)
	}
}

// Retroactive consent is the failure this refusal exists for: a customer agrees today
// and runs collected while they had agreed to nothing silently become training data.
// The record would look perfectly consistent afterwards, which is why the check has to
// be structural rather than a review step.
func TestGrantConsent_IsNotRetroactive(t *testing.T) {
	e := NewEpisode(&Ledger{AgentKind: "cloudagent"}, st("s", nil, nil, nil))
	if err := e.GrantConsent("owner@acme.test", "may be used to improve detection", time.Unix(1, 0)); err != nil {
		t.Fatalf("consent before close must be accepted: %v", err)
	}
	if !e.Trainable() {
		t.Error("a consented episode must be trainable")
	}

	closed := NewEpisode(&Ledger{AgentKind: "cloudagent"}, st("s", nil, nil, nil))
	if err := closed.Close(st("s", nil, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if err := closed.GrantConsent("owner@acme.test", "x", time.Unix(2, 0)); !errors.Is(err, ErrConsentNotRetroactive) {
		t.Errorf("consent after the episode is written must be refused, got %v", err)
	}
	if closed.Trainable() {
		t.Error("a refused grant must leave the episode non-trainable")
	}
}

// A run whose posture change could not be measured is still a real run. Dropping it
// would bias the corpus toward exactly the episodes that went smoothly.
func TestClose_KeepsTheEpisodeWhenTheDeltaFails(t *testing.T) {
	e := NewEpisode(&Ledger{AgentKind: "webagent"}, st("web:acme", []string{"a"}, nil, nil))
	err := e.Close(st("aws:1", []string{"b"}, nil, nil))
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("want the mismatch reported, got %v", err)
	}
	if e.Delta != nil {
		t.Error("an unscorable episode must carry no delta rather than a wrong one")
	}
	if e.After == nil {
		t.Error("the after-state is still what was observed and must be retained")
	}
}

// An episode that verified nothing has no cost per outcome. Returning zero would make
// the agent that finds nothing look like the cheapest one in any fleet average.
func TestCostPerVerified_NoOutcomeIsNotZero(t *testing.T) {
	e := &Episode{Cost: Cost{USD: 4}}
	if _, ok := e.CostPerVerified(0); ok {
		t.Error("zero verified outcomes must report no ratio, not a ratio of zero")
	}
	got, ok := e.CostPerVerified(2)
	if !ok || got != 2 {
		t.Errorf("CostPerVerified(2) = %v, %v; want 2, true", got, ok)
	}
}

// Failed episodes are retained and trainable. An agent that only ever sees its
// successes learns that everything works.
func TestTrainable_FailureIsNotAGate(t *testing.T) {
	e := NewEpisode(&Ledger{AgentKind: "webagent"}, st("s", nil, nil, nil))
	_ = e.GrantConsent("o", "s", time.Unix(1, 0))
	e.StopReason = "stalled"
	e.Verification = "pattern_match"
	if !e.Trainable() {
		t.Error("consent alone gates training; a stalled run is a first-class example")
	}
}

func TestRecorder_ChargeAndGround(t *testing.T) {
	r := NewRecorder().WithClock(func() time.Time { return time.Unix(0, 0).UTC() })
	r.Record("thinking", "find_paths", nil, "3 paths")
	r.Charge(0.02, 1500)
	if !r.Ground(1, "d-1") {
		t.Fatal("Ground on an existing step must succeed")
	}
	if r.Ground(99, "d-1") {
		t.Error("Ground on a step that does not exist must report false, not land silently")
	}
	got := r.Steps()[0]
	if got.CostUSD != 0.02 || got.Tokens != 1500 || got.VerifiedBy != "d-1" {
		t.Errorf("step = %+v", got)
	}

	// Nil-safety is the package's contract — an agent calls these unconditionally.
	var nilr *Recorder
	nilr.Charge(1, 1)
	if nilr.Ground(1, "x") {
		t.Error("Ground on a nil recorder must be false")
	}
}

// Charging before any step exists must not panic and must not invent a step.
func TestRecorder_ChargeBeforeAnyStep(t *testing.T) {
	r := NewRecorder()
	r.Charge(1, 1)
	if r.Len() != 0 {
		t.Errorf("Charge must not create a step; Len = %d", r.Len())
	}
}
