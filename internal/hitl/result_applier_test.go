package hitl

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ticketApplier returns the action as delivered, carrying the ticket the tracker created — and also
// tries to change fields delivery must NOT be able to set.
type ticketApplier struct{}

func (ticketApplier) Apply(context.Context, platform.Action) error { return nil }
func (ticketApplier) ApplyResult(_ context.Context, a platform.Action) (platform.Action, error) {
	a.Ticket = &platform.TicketRef{System: "jira", Key: "SEC-7", Destination: "tenant"}
	a.Approver = "delivery-tried-to-sign" // must not survive
	a.Tier = 0                            // must not survive
	return a, nil
}

// The desk persists its OWN copy right after applying, so a ticket reference stored any other way is
// overwritten. Through ResultApplier it survives — and nothing else delivery returns does.
func TestDeskPersistsTheDeliveredTicketAndNothingElse(t *testing.T) {
	d, _, st := newDesk(ticketApplier{})
	a := platform.Action{ID: "a1", TenantID: "t", Tier: 1, Kind: platform.ActFileTicket, Status: platform.ActProposed}
	if _, err := d.Submit(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAction(context.Background(), "t", "a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Ticket == nil || got.Ticket.Key != "SEC-7" {
		t.Fatalf("the delivered ticket must be persisted, got %+v", got.Ticket)
	}
	if got.Approver == "delivery-tried-to-sign" || got.Tier != 1 {
		t.Fatalf("delivery may set the ticket only: approver=%q tier=%d", got.Approver, got.Tier)
	}
}
