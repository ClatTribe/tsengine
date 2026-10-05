package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

const ctRootWithID = `{"eventID":"ev-root-1","userIdentity":{"type":"Root","arn":"arn:aws:iam::1:root"},"eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9"}`

func pollFixture(t *testing.T) (*store.Memory, *Service, *fakeTrail, *time.Time) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutConnection(ctx, platform.Connection{ID: "aws1", TenantID: "t1", Kind: platform.ConnAWS, Status: platform.ConnActive, SecretRef: "arn:aws:iam::1:role/ro"})
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tr := &fakeTrail{page: awsfetch.EventPage{Records: [][]byte{[]byte(ctRootWithID)}, Latest: now.Add(-2 * time.Minute)}}
	n := 0
	id := func() string { n++; return itoa(n) }
	svc := &Service{Store: st, NewID: id, Now: func() time.Time { return now },
		CloudEventReader: func(platform.Connection) awsfetch.EventReader { return tr },
		Detector:         &detect.Detector{Store: st, NewID: id, Now: func() time.Time { return now }}}
	return st, svc, tr, &now
}

// A root login opens an incident on the fast poll, not at the next full pass — and re-reading the
// overlapping window on the next poll reports it ONCE, not once per poll.
func TestPollEvents_OpensAnIncidentAndDoesNotDuplicateOnReRead(t *testing.T) {
	ctx := context.Background()
	st, svc, _, _ := pollFixture(t)

	res := svc.PollEvents(ctx, "t1")
	if !res.CloudRead || res.Findings != 1 || res.Opened != 1 {
		t.Fatalf("first poll: %+v", res)
	}
	for i := 0; i < 3; i++ { // the same event, re-read inside the overlap
		svc.PollEvents(ctx, "t1")
	}
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) != 1 {
		t.Errorf("one event re-read four times must be one finding, got %d", len(fs))
	}
	incs, _ := st.ListIncidents(ctx, "t1")
	if len(incs) != 1 {
		t.Errorf("one event must be one incident, got %d", len(incs))
	}
}

// The kill-switch pauses scanning; reading the customer's logs is scanning.
func TestPollEvents_HaltedTenantIsNotRead(t *testing.T) {
	ctx := context.Background()
	st, svc, tr, _ := pollFixture(t)
	tn, _ := st.GetTenant(ctx, "t1")
	tn.AgentsHalted = true
	_ = st.PutTenant(ctx, tn)
	if res := svc.PollEvents(ctx, "t1"); res.CloudRead || tr.calls != 0 {
		t.Errorf("a halted tenant's logs were read: %+v calls=%d", res, tr.calls)
	}
}

// The bug this closes: an event incident used to be resolved by the full pass once the event was no
// longer re-read — a root login reading as "resolved" a day later because it did not happen again.
func TestFullPass_DoesNotResolveAnEventIncidentByAbsence(t *testing.T) {
	ctx := context.Background()
	st, svc, tr, _ := pollFixture(t)
	svc.PollEvents(ctx, "t1")
	tr.page = awsfetch.EventPage{} // nothing new in later windows

	for i := 0; i < 4; i++ {
		if _, err := svc.Detector.ReconcileScoped(ctx, "t1", nil, nil, detect.AllProducers()); err != nil {
			t.Fatal(err)
		}
	}
	incs, _ := st.ListIncidents(ctx, "t1")
	if len(incs) != 1 || incs[0].Status != platform.IncidentOpen {
		t.Fatalf("an event incident must stay open until a person closes it: %+v", incs)
	}
}
