package runner

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/ticketsync"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type doneTracker struct{ comments int }

func (d *doneTracker) TicketStatus(context.Context, string) (connector.IssueStatus, error) {
	return connector.IssueStatus{Name: "Done", Category: "done"}, nil
}
func (d *doneTracker) AddComment(context.Context, string, string) error { d.comments++; return nil }

// The sync must write ONLY the ticket: the action it read may already be stale, and writing it back
// whole could undo a verification the pass just recorded.
func TestSyncTickets_WritesOnlyTheTicket(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	act := platform.Action{ID: "a1", TenantID: "t1", Status: platform.ActApplied,
		Ticket: &platform.TicketRef{System: "jira", Key: "SEC-1", Destination: "tenant"}}
	_ = st.PutAction(ctx, act)

	tr := &doneTracker{}
	s := &Service{Store: st, TicketTracker: func(context.Context, string, platform.TicketRef) (ticketsync.Tracker, error) {
		// Simulate the full pass recording a verification WHILE the sync is between its read and its write.
		fresh, _ := st.GetAction(ctx, "t1", "a1")
		fresh.Verification = &platform.FixVerification{Status: platform.FixStatusFixed, VerifiedAt: time.Now()}
		_ = st.PutAction(ctx, fresh)
		return tr, nil
	}}
	res := s.syncTickets(ctx, "t1")
	got, _ := st.GetAction(ctx, "t1", "a1")
	if res.NewlyResolved != 1 || got.Ticket == nil || !got.Ticket.Resolved {
		t.Fatalf("ticket view not persisted: %+v %+v", res, got.Ticket)
	}
	if got.Verification == nil || got.Verification.Status != platform.FixStatusFixed {
		t.Fatal("the sync overwrote a verification recorded during it — it must write only the ticket")
	}
}

func TestSyncTickets_HaltedTenantIsNotRead(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", AgentsHalted: true})
	_ = st.PutAction(ctx, platform.Action{ID: "a1", TenantID: "t1", Status: platform.ActApplied,
		Ticket: &platform.TicketRef{System: "jira", Key: "SEC-1", Destination: "tenant"}})
	called := false
	s := &Service{Store: st, TicketTracker: func(context.Context, string, platform.TicketRef) (ticketsync.Tracker, error) {
		called = true
		return &doneTracker{}, nil
	}}
	s.syncTickets(ctx, "t1")
	if called {
		t.Fatal("the kill-switch pauses the agent — that includes writing comments into the customer's Jira")
	}
}
