package detect

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// fakeTriager returns a fixed verdict for every finding.
type fakeTriager struct {
	v      SkillVerdict
	ok     bool
	called int
}

func (f *fakeTriager) Triage(context.Context, types.Finding, []types.Finding) (SkillVerdict, bool) {
	f.called++
	return f.v, f.ok
}

func triageDetector(t *testing.T, tr SkillTriager) (*Detector, *memStore) {
	t.Helper()
	st := &memStore{}
	return &Detector{Store: st, Triager: tr, Threshold: types.SeverityHigh,
		NewID: func() string { return "inc-1" }}, st
}

func highFinding() types.Finding {
	return types.Finding{ID: "f-001", RuleID: "operate::stale-account", Severity: types.SeverityHigh,
		Title: "Stale account", Endpoint: "ada@acme.io"}
}

func TestReconcile_AnnotatesOpeningIncidentWithVerdict(t *testing.T) {
	tr := &fakeTriager{v: SkillVerdict{Verdict: "suspicious", Rationale: "why", Skill: "stale@abc123"}, ok: true}
	d, _ := triageDetector(t, tr)

	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{highFinding()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(res.Opened))
	}
	inc := res.Opened[0]
	if inc.TriageVerdict != "suspicious" || inc.TriageRationale != "why" || inc.TriageSkill != "stale@abc123" {
		t.Fatalf("the alert did not inherit the skill's reasoning: %+v", inc)
	}
	if tr.called != 1 {
		t.Errorf("triager called %d times, want 1", tr.called)
	}
}

// THE SAFETY PROPERTY. A skill is third-party input. If a "benign" verdict could stop an incident
// opening, anyone who can publish a skill would have a mute button on the SOC. The incident must
// open regardless — the verdict only explains it.
func TestReconcile_BenignVerdictCannotSuppressTheIncident(t *testing.T) {
	tr := &fakeTriager{v: SkillVerdict{Verdict: "benign", Rationale: "nothing to see"}, ok: true}
	d, _ := triageDetector(t, tr)

	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{highFinding()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("a benign verdict MUST NOT suppress the incident — that would be a mute button on the SOC; opened=%d", len(res.Opened))
	}
	if res.Opened[0].TriageVerdict != "benign" {
		t.Errorf("the verdict should still be recorded as context: %+v", res.Opened[0])
	}
	if res.Opened[0].Severity != string(types.SeverityHigh) {
		t.Error("a verdict must not alter severity either")
	}
}

// Triage is best-effort: a triager that declines leaves the alert exactly as it is today.
func TestReconcile_NoAnnotationWhenTriagerDeclines(t *testing.T) {
	d, _ := triageDetector(t, &fakeTriager{ok: false})
	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{highFinding()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("expected the incident to open anyway, got %d", len(res.Opened))
	}
	if res.Opened[0].TriageVerdict != "" {
		t.Errorf("expected no annotation, got %+v", res.Opened[0])
	}
}

// A nil Triager is the default: today's behaviour, unchanged.
func TestReconcile_NilTriagerIsUnchangedBehaviour(t *testing.T) {
	d, _ := triageDetector(t, nil)
	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{highFinding()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 || res.Opened[0].TriageVerdict != "" {
		t.Fatalf("nil triager must behave exactly as before: %+v", res.Opened)
	}
}

// A finding BELOW the threshold must not be triaged at all — triage costs a model call, and running
// it on findings that will never open an incident would be pure waste.
func TestReconcile_SubThresholdFindingIsNotTriaged(t *testing.T) {
	tr := &fakeTriager{v: SkillVerdict{Verdict: "benign"}, ok: true}
	d, _ := triageDetector(t, tr)

	low := highFinding()
	low.Severity = types.SeverityLow
	res, err := d.Reconcile(context.Background(), "t1", []types.Finding{low}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 0 {
		t.Fatalf("a low-severity finding should not open an incident, got %d", len(res.Opened))
	}
	if tr.called != 0 {
		t.Errorf("triage should not run for findings that never open an incident; called %d times", tr.called)
	}
}

// memStore is a minimal in-memory Store for these tests.
type memStore struct{ incidents []platform.Incident }

func (m *memStore) PutIncident(_ context.Context, i platform.Incident) error {
	for idx := range m.incidents {
		if m.incidents[idx].ID == i.ID {
			m.incidents[idx] = i
			return nil
		}
	}
	m.incidents = append(m.incidents, i)
	return nil
}

func (m *memStore) ListIncidents(_ context.Context, _ string) ([]platform.Incident, error) {
	return append([]platform.Incident(nil), m.incidents...), nil
}
