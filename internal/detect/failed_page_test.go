package detect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type failingAlerter struct{ calls int }

func (f *failingAlerter) IncidentOpened(context.Context, platform.Incident) error {
	f.calls++
	return errors.New("slack webhook 503")
}

type okAlerter struct{ calls int }

func (o *okAlerter) IncidentOpened(context.Context, platform.Incident) error {
	o.calls++
	return nil
}

func overdueIncident(t *testing.T, st store.Store, id string) {
	t.Helper()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutIncident(ctx, platform.Incident{
		ID: id, TenantID: "t1", Status: platform.IncidentOpen,
		Severity: "critical", Title: "prod database is public",
		OpenedAt: time.Now().UTC().Add(-48 * time.Hour),
	})
}

// A page that did not land is not an escalation.
//
// The error was discarded and LastEscalatedAt stamped regardless, which on a Slack or PagerDuty
// outage recorded incident_escalated in the SIGNED ledger, showed the incident as escalated, and —
// because Overdue allows at most one re-ping per window — SUPPRESSED the retry for a whole window.
// The one mechanism that exists to stop a critical incident being ignored went quiet exactly when
// the alerting path was broken.
func TestEscalateOverdue_AFailedPageIsNotRecordedAndRetriesNextPass(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	overdueIncident(t, st, "inc-1")
	al := &failingAlerter{}
	d := &Detector{Store: st, Alerter: al, NewID: func() string { return "x" }}

	esc, err := d.EscalateOverdue(ctx, "t1", 60)
	if err != nil {
		t.Fatalf("a failed page must not fail the pass: %v", err)
	}
	if len(esc) != 0 {
		t.Errorf("an incident nobody was paged about must not be reported as escalated, got %d", len(esc))
	}
	if !incByID(t, st, "inc-1").LastEscalatedAt.IsZero() {
		t.Error("LastEscalatedAt was stamped for a page that failed — Overdue then suppresses the " +
			"retry for a whole window, so the next pass would stay silent too")
	}

	// The point of not stamping: the NEXT pass tries again.
	if _, err := d.EscalateOverdue(ctx, "t1", 60); err != nil {
		t.Fatal(err)
	}
	if al.calls != 2 {
		t.Errorf("the next pass must retry a page that did not send, got %d attempt(s)", al.calls)
	}
}

// The control: a page that DID send is recorded, and is not re-sent every pass afterwards.
func TestEscalateOverdue_ASuccessfulPageIsRecordedAndNotRepeated(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	overdueIncident(t, st, "inc-2")
	al := &okAlerter{}
	d := &Detector{Store: st, Alerter: al, NewID: func() string { return "x" }}

	esc, err := d.EscalateOverdue(ctx, "t1", 60)
	if err != nil || len(esc) != 1 {
		t.Fatalf("a delivered page is a real escalation: esc=%d err=%v", len(esc), err)
	}
	if incByID(t, st, "inc-2").LastEscalatedAt.IsZero() {
		t.Fatal("a delivered page must be recorded, or every pass re-pages the same incident")
	}
	if _, err := d.EscalateOverdue(ctx, "t1", 60); err != nil {
		t.Fatal(err)
	}
	if al.calls != 1 {
		t.Errorf("one re-ping per window — got %d, which is how an on-call gets trained to mute us", al.calls)
	}
}

func incByID(t *testing.T, st store.Store, id string) platform.Incident {
	t.Helper()
	all, err := st.ListIncidents(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range all {
		if i.ID == id {
			return i
		}
	}
	t.Fatalf("incident %s not found", id)
	return platform.Incident{}
}
