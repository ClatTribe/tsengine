package funnel

import (
	"strings"
	"testing"
	"time"
)

var (
	from = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	to   = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	now  = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
)

func at(day int) time.Time { return from.AddDate(0, 0, day) }

func stage(r Report, key string) Stage {
	for _, s := range r.Stages {
		if s.Key == key {
			return s
		}
	}
	panic("no stage " + key)
}

func rateOf(r Report, from, to string) Rate {
	for _, x := range r.Rates {
		if x.From == from && x.To == to {
			return x
		}
	}
	panic("no rate " + from + "→" + to)
}

func TestCountsTheCohortAndConverts(t *testing.T) {
	in := Input{From: from, To: to, Now: now, FreeScans: 400, ScansMeasured: true, Journeys: []Journey{
		// full activation
		{TenantID: "a", SignedUpAt: at(1), ConnectedAt: at(1), FirstFindingAt: at(2), AgentEnabled: true},
		// connected + finding, agent off
		{TenantID: "b", SignedUpAt: at(3), ConnectedAt: at(3), FirstFindingAt: at(4)},
		// connected, nothing found yet
		{TenantID: "c", SignedUpAt: at(5), ConnectedAt: at(6)},
		// signed up, never connected
		{TenantID: "d", SignedUpAt: at(7)},
	}}
	r := Compute(in)

	for _, tc := range []struct {
		key  string
		want int
	}{
		{StageSignup, 4}, {StageConnect, 3}, {StageFirstFinding, 2}, {StageAgentEnabled, 1},
	} {
		if got := stage(r, tc.key).Count; got != tc.want {
			t.Errorf("%s = %d, want %d", tc.key, got, tc.want)
		}
	}
	if p := rateOf(r, StageSignup, StageConnect).Pct; p != 75 {
		t.Errorf("signup→connect = %v, want 75", p)
	}
	if p := rateOf(r, StageConnect, StageFirstFinding).Pct; p < 66.6 || p > 66.7 {
		t.Errorf("connect→finding = %v, want ~66.67", p)
	}
	if p := rateOf(r, StageFirstFinding, StageAgentEnabled).Pct; p != 50 {
		t.Errorf("finding→agent = %v, want 50", p)
	}
}

// Rule 2, and the most likely misreading of any funnel: an empty cohort is not a failed one.
// Printing 0% on a quiet fortnight makes a working product look broken.
func TestEmptyCohortIsUnknownNotZeroPercent(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, ScansMeasured: true})

	for _, x := range r.Rates {
		if x.Measured {
			t.Errorf("rate %s→%s claims to be measured on an empty cohort", x.From, x.To)
		}
	}
	got := rateOf(r, StageSignup, StageConnect)
	if got.Pct != 0 || got.Measured {
		t.Errorf("empty cohort rate = %+v, want unmeasured", got)
	}
	if !strings.Contains(got.Note, "not 0%") {
		t.Errorf("note does not distinguish unknown from zero: %q", got.Note)
	}
	// The STAGES are legitimately zero — nobody signed up. That is a real count, not a gap.
	if s := stage(r, StageSignup); !s.Measured || s.Count != 0 {
		t.Errorf("signup stage = %+v, want measured count 0", s)
	}
}

// Rule 1: a missing counter must not render as "nobody ran a scan".
func TestUnwiredScanCounterIsUnmeasuredNotZero(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, ScansMeasured: false})
	s := stage(r, StageFreeScan)
	if s.Measured {
		t.Error("free-scan stage claims to be measured with no counter wired")
	}
	if !strings.Contains(strings.ToLower(s.Note), "not zero") {
		t.Errorf("note does not say unknown-vs-zero: %q", s.Note)
	}
}

// Rule 3: the top link is refused on purpose, and the refusal has to SAY it is a choice —
// a blank reads as an oversight somebody will later "fix" by logging scanned domains.
func TestScanToSignupIsDeclinedNotSilentlyMissing(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, FreeScans: 100, ScansMeasured: true})
	x := rateOf(r, StageFreeScan, StageSignup)
	if x.Measured {
		t.Fatal("scan→signup reports a number; it cannot be computed without storing who scanned")
	}
	low := strings.ToLower(x.Note)
	if !strings.Contains(low, "decline") && !strings.Contains(low, "choice") {
		t.Errorf("the refusal does not read as deliberate: %q", x.Note)
	}
}

// The window is a cohort definition; a tenant outside it must not be counted even if they
// activated during it. Getting this wrong inflates every rate.
func TestOnlyTheSignupCohortIsCounted(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, ScansMeasured: true, Journeys: []Journey{
		{TenantID: "before", SignedUpAt: from.AddDate(0, 0, -1), ConnectedAt: at(2), AgentEnabled: true},
		{TenantID: "after", SignedUpAt: to, ConnectedAt: to},
		{TenantID: "in", SignedUpAt: at(0)},
	}})
	if got := stage(r, StageSignup).Count; got != 1 {
		t.Errorf("signup = %d, want 1 — only the in-window tenant", got)
	}
	if got := stage(r, StageConnect).Count; got != 0 {
		t.Errorf("connect = %d, want 0 — the out-of-cohort tenants' connections must not count", got)
	}
}

// From is inclusive and To exclusive, so adjacent windows tile without double-counting.
func TestWindowBoundariesTile(t *testing.T) {
	if !inWindow(from, from, to) {
		t.Error("From must be inclusive")
	}
	if inWindow(to, from, to) {
		t.Error("To must be exclusive, or adjacent windows double-count")
	}
	if inWindow(time.Time{}, from, to) {
		t.Error("the zero time means 'never happened' and must never fall in a window")
	}
}

// Stages are counted independently, not as a cascade. A tenant with a finding from a posted
// snapshot and no connection is real; capping later stages at earlier ones would report that
// as a drop-off at a step they legitimately skipped.
func TestStagesAreNotCappedByEarlierOnes(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, ScansMeasured: true, Journeys: []Journey{
		{TenantID: "snapshot-only", SignedUpAt: at(1), FirstFindingAt: at(2), AgentEnabled: true},
	}})
	if c := stage(r, StageConnect).Count; c != 0 {
		t.Errorf("connect = %d, want 0", c)
	}
	if f := stage(r, StageFirstFinding).Count; f != 1 {
		t.Errorf("first_finding = %d, want 1 — a finding without a connection is still a finding", f)
	}
	// …and the rate out of an empty stage is unknown, not a division by zero.
	if x := rateOf(r, StageConnect, StageFirstFinding); x.Measured {
		t.Error("connect→finding reports a rate with a zero denominator")
	}
}

// Every stage must explain where its number came from, or the report is a set of figures a
// reader can only trust rather than check.
func TestEveryStageCarriesItsBasis(t *testing.T) {
	r := Compute(Input{From: from, To: to, Now: now, ScansMeasured: true})
	for _, s := range r.Stages {
		if strings.TrimSpace(s.Basis) == "" {
			t.Errorf("stage %s has no basis", s.Key)
		}
		if strings.TrimSpace(s.Label) == "" {
			t.Errorf("stage %s has no label", s.Key)
		}
	}
	if !strings.Contains(r.Cohort, "Not activity within the window") {
		t.Error("the report does not state that it is a cohort, so it reads as period activity")
	}
}

// The bug this guards was found by running the funnel against real data: paid plans entitle
// the agent, so on a platform of paying customers "agent enabled" is true for everyone the
// instant they sign up, the final rate reads a permanent 100%, and the stage measures what we
// SOLD them rather than anything they did. The count stays — it is a true statement about
// capability — but the report must say which half is which, or the number cannot inform.
func TestAgentStageSeparatesConfiguredFromMerelyEntitled(t *testing.T) {
	in := Input{From: from, To: to, Now: now, ScansMeasured: true, Journeys: []Journey{
		{TenantID: "own", SignedUpAt: at(1), AgentEnabled: true, AgentOwnKey: true},
		{TenantID: "plan1", SignedUpAt: at(2), AgentEnabled: true},
		{TenantID: "plan2", SignedUpAt: at(3), AgentEnabled: true},
		{TenantID: "off", SignedUpAt: at(4)},
	}}
	s := stage(Compute(in), StageAgentEnabled)
	if s.Count != 3 {
		t.Fatalf("agent_enabled = %d, want 3", s.Count)
	}
	if !strings.Contains(s.Note, "1 configured") {
		t.Errorf("note does not report how many took the deliberate act: %q", s.Note)
	}
	if !strings.Contains(s.Note, "2 are entitled") {
		t.Errorf("note does not report how many are merely entitled: %q", s.Note)
	}
}

// The all-entitled case is the one that actually misleads, so it gets its own wording: the
// stage is measuring the plan, and the report has to say so out loud.
func TestAgentStageSaysSoWhenNobodyActuallyConfiguredIt(t *testing.T) {
	s := stage(Compute(Input{From: from, To: to, Now: now, ScansMeasured: true, Journeys: []Journey{
		{TenantID: "a", SignedUpAt: at(1), AgentEnabled: true},
		{TenantID: "b", SignedUpAt: at(2), AgentEnabled: true},
	}}), StageAgentEnabled)
	low := strings.ToLower(s.Note)
	if !strings.Contains(low, "what they were sold") {
		t.Errorf("an all-entitled cohort must be flagged as measuring the plan, not activation: %q", s.Note)
	}
}
