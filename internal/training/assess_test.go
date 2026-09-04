package training

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func assessFor(t *testing.T, people []Person, comps []Completion, at time.Time) []types.Finding {
	t.Helper()
	return Assess(Evaluate(Default(), people, comps, at), at)
}

// A fully-trained roster produces nothing — the grounding rule every posture assessor here follows.
// The caller stamps that the assessment RAN, because zero findings and never having looked must not
// read the same.
func TestAFullyTrainedRosterYieldsNoFindings(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: SourceHRIS}}
	var comps []Completion
	for _, m := range Default().Modules {
		comps = append(comps, mustComplete(t, "ada@acme.io", m.ID, TierDelivered, "", "", now.AddDate(0, 0, -5)))
	}
	if got := assessFor(t, people, comps, now); len(got) != 0 {
		t.Fatalf("a current roster produced %d findings: %+v", len(got), got)
	}
}

// One row per PERSON, not per assignment. Five modules across forty people is two hundred rows, and
// an issues list that size is one people learn to scroll past.
func TestOneFindingPerPersonNotPerAssignment(t *testing.T) {
	people := []Person{
		{Email: "ada@acme.io", Name: "Ada", Source: SourceHRIS},
		{Email: "grace@acme.io", Source: SourceApp},
	}
	got := assessFor(t, people, nil, now)
	if len(got) != 2 {
		t.Fatalf("want 1 finding per person (2), got %d", len(got))
	}
	for _, f := range got {
		if f.Endpoint != "ada@acme.io" && f.Endpoint != "grace@acme.io" {
			t.Errorf("endpoint %q is not the person, so the dedup key is not stable per person", f.Endpoint)
		}
	}
}

// The endpoint is the person, so the (rule|endpoint) key is stable across passes: the row closes
// when they finish rather than a new one appearing every scan.
func TestTheKeyIsStableAcrossPassesAndClosesWhenTheyFinish(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: SourceHRIS}}
	first := assessFor(t, people, nil, now)
	later := assessFor(t, people, nil, now.AddDate(0, 0, 7))
	if len(first) != 1 || len(later) != 1 {
		t.Fatalf("want one finding each pass, got %d then %d", len(first), len(later))
	}
	if first[0].RuleID != later[0].RuleID || first[0].Endpoint != later[0].Endpoint {
		t.Errorf("the key moved between passes: %s|%s then %s|%s",
			first[0].RuleID, first[0].Endpoint, later[0].RuleID, later[0].Endpoint)
	}

	var comps []Completion
	for _, m := range Default().Modules {
		comps = append(comps, mustComplete(t, "ada@acme.io", m.ID, TierDelivered, "", "", now))
	}
	if got := assessFor(t, people, comps, now.AddDate(0, 0, 1)); len(got) != 0 {
		t.Fatalf("the finding survived the person completing everything: %+v", got)
	}
}

// Never-started and lapsed are different problems and the finding says which — including WHEN it
// lapsed, because "overdue" is a state and "overdue since March" is a fact somebody can act on.
func TestTheFindingSeparatesNeverStartedFromLapsedAndDatesTheLapse(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: SourceHRIS}}
	comps := []Completion{mustComplete(t, "ada@acme.io", "phishing", TierDelivered, "", "", now.AddDate(0, 0, -400))}
	got := assessFor(t, people, comps, now)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	d := got[0].Description
	if !strings.Contains(d, "Not started:") {
		t.Error("the description does not name the modules never started")
	}
	if !strings.Contains(d, "Completed too long ago") {
		t.Error("the description does not distinguish a lapsed module from one never started")
	}
	if !strings.Contains(d, "due again since") {
		t.Error("the lapse is not dated — 'overdue' alone is not something an auditor can check")
	}
	if !strings.Contains(got[0].Title, "outstanding") || !strings.Contains(got[0].Title, "lapsed") {
		t.Errorf("the title collapses the two states: %q", got[0].Title)
	}
}

// MEDIUM, deliberately: a control gap, not an exploitable weakness. High and above opens an
// incident, and paging someone at night over a training reminder is how an alerting channel dies.
func TestTrainingGapsAreMediumSoTheyDoNotPageAnybody(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: SourceHRIS}}
	for _, f := range assessFor(t, people, nil, now) {
		if f.Severity != types.SeverityMedium {
			t.Errorf("severity = %s; a missing training module is not an incident", f.Severity)
		}
	}
}

// The control nexus is what makes this compliance evidence: a gap is opened only because a real
// finding cites a control (§18.2 inv. 5).
func TestTheFindingCarriesTheAwarenessControlNexus(t *testing.T) {
	people := []Person{{Email: "ada@acme.io", Source: SourceHRIS}}
	got := assessFor(t, people, nil, now)
	if len(got) != 1 || got[0].Compliance == nil {
		t.Fatalf("no compliance annotation: %+v", got)
	}
	c := got[0].Compliance
	if len(c.SOC2) == 0 || len(c.ISO27001) == 0 || len(c.PCI) == 0 || len(c.HIPAA) == 0 {
		t.Errorf("the awareness controls are not all carried: %+v", c)
	}
	// The finding and the module must cite the SAME controls — they are one claim from two
	// directions, and two lists would drift.
	if want := awarenessControls()["soc2"]; strings.Join(c.SOC2, ",") != strings.Join(want, ",") {
		t.Errorf("SOC2 refs = %v, curriculum says %v", c.SOC2, want)
	}
}

// The roster: active employees plus this product's users, HRIS winning a duplicate, leavers out.
func TestRosterFromPrefersTheHRISRecordAndDropsLeavers(t *testing.T) {
	emps := []platform.Employee{
		{WorkEmail: "Ada@acme.io", Name: "Ada Lovelace", Status: platform.EmploymentActive},
		{WorkEmail: "gone@acme.io", Name: "Gone", Status: platform.EmploymentTerminated},
	}
	users := []platform.User{
		{Email: "ada@acme.io", Name: "ada"},
		{Email: "grace@acme.io", Name: "Grace"},
	}
	got := RosterFrom(emps, users)
	if len(got) != 2 {
		t.Fatalf("roster = %+v, want ada + grace", got)
	}
	byEmail := map[string]Person{}
	for _, p := range got {
		byEmail[p.Email] = p
	}
	ada, ok := byEmail["ada@acme.io"]
	if !ok {
		t.Fatal("ada is missing — the HRIS address was not normalised")
	}
	if ada.Source != SourceHRIS || ada.Name != "Ada Lovelace" {
		t.Errorf("the user record beat the HRIS one: %+v", ada)
	}
	if _, leaver := byEmail["gone@acme.io"]; leaver {
		t.Error("a terminated employee is on the roster")
	}
	if byEmail["grace@acme.io"].Source != SourceApp {
		t.Errorf("grace's source = %q", byEmail["grace@acme.io"].Source)
	}
}
