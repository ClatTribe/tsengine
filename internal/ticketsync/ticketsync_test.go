package ticketsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type fakeTracker struct {
	status   map[string]connector.IssueStatus
	readErr  error
	comments map[string][]string
	failPost bool
}

func (f *fakeTracker) TicketStatus(_ context.Context, key string) (connector.IssueStatus, error) {
	if f.readErr != nil {
		return connector.IssueStatus{}, f.readErr
	}
	return f.status[key], nil
}
func (f *fakeTracker) AddComment(_ context.Context, key, text string) error {
	if f.failPost {
		return errors.New("HTTP 403")
	}
	if f.comments == nil {
		f.comments = map[string][]string{}
	}
	f.comments[key] = append(f.comments[key], text)
	return nil
}

func trackerOf(f *fakeTracker) TrackerFor {
	return func(context.Context, string, platform.TicketRef) (Tracker, error) { return f, nil }
}

var t0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

func action(id string, v *platform.FixVerification, tk platform.TicketRef) platform.Action {
	tk.System, tk.Destination = "jira", "tenant"
	return platform.Action{ID: id, TenantID: "t1", Status: platform.ActApplied, Verification: v, Ticket: &tk}
}

func TestSync_ClosedButStillPresentIsSurfacedAndToldOnce(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{"SEC-1": {Name: "Won't Do", Category: "done", ResolvedAt: t0}}}
	v := &platform.FixVerification{Status: platform.FixStatusStillPresent, VerifiedAt: t0.Add(time.Hour), Evidence: "1 of 1 still present"}
	acts := []platform.Action{action("a1", v, platform.TicketRef{Key: "SEC-1"})}

	changed, res := Sync(context.Background(), acts, trackerOf(f), t0.Add(2*time.Hour), Options{Comments: true})
	if res.NewlyResolved != 1 || res.ClosedStillPresent != 1 || res.Commented != 1 {
		t.Fatalf("%+v", res)
	}
	tk := changed[0].Ticket
	if !tk.Resolved || !tk.ClosedStillPresent || tk.Notified != "still_present" || tk.Status != "Won't Do" {
		t.Fatalf("ticket view wrong: %+v", tk)
	}
	if c := f.comments["SEC-1"]; len(c) != 1 || !strings.Contains(c[0], "STILL PRESENT") || !strings.Contains(c[0], "does not reopen") {
		t.Fatalf("comment wrong: %v", c)
	}
	// Next pass: same state — nothing new to say.
	_, res2 := Sync(context.Background(), changed, trackerOf(f), t0.Add(3*time.Hour), Options{Comments: true})
	if res2.Commented != 0 {
		t.Fatal("an outcome must be posted once, not every pass")
	}
}

// A still_present verdict from BEFORE the close says nothing about whether the close was premature.
func TestSync_StaleVerdictDoesNotCountAsADisagreement(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{"SEC-2": {Name: "Done", Category: "done", ResolvedAt: t0}}}
	v := &platform.FixVerification{Status: platform.FixStatusStillPresent, VerifiedAt: t0.Add(-time.Hour)}
	changed, res := Sync(context.Background(), []platform.Action{action("a2", v, platform.TicketRef{Key: "SEC-2"})},
		trackerOf(f), t0.Add(time.Hour), Options{Comments: true})
	if res.ClosedStillPresent != 0 || changed[0].Ticket.ClosedStillPresent || len(f.comments) != 0 {
		t.Fatalf("a verdict older than the close must not be read as one: %+v", changed[0].Ticket)
	}
}

// The category decides done, never the name: "Shipped" in one workflow is done; "Done-ish" is not.
func TestSync_CategoryNotNameDecidesDone(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{
		"A": {Name: "Shipped", Category: "done"},
		"B": {Name: "Done-ish (waiting on QA)", Category: "indeterminate"},
	}}
	acts := []platform.Action{action("a", nil, platform.TicketRef{Key: "A"}), action("b", nil, platform.TicketRef{Key: "B"})}
	changed, _ := Sync(context.Background(), acts, trackerOf(f), t0, Options{})
	got := map[string]bool{}
	for _, a := range changed {
		got[a.Ticket.Key] = a.Ticket.Resolved
	}
	if !got["A"] || got["B"] {
		t.Fatalf("resolution must follow the category: %v", got)
	}
}

// A ticket we cannot read is not an open ticket — the previous view stands and the error is recorded.
func TestSync_UnreadableKeepsThePreviousViewAndSaysWhy(t *testing.T) {
	f := &fakeTracker{readErr: errors.New("jira: read SEC-3: HTTP 401")}
	prev := platform.TicketRef{Key: "SEC-3", Resolved: true, ResolvedAt: t0, Status: "Done", StatusCategory: "done"}
	changed, res := Sync(context.Background(), []platform.Action{action("a3", nil, prev)}, trackerOf(f), t0.Add(time.Hour), Options{})
	tk := changed[0].Ticket
	if res.ReadFailed != 1 || !tk.Resolved || tk.Status != "Done" || !strings.Contains(tk.SyncError, "401") {
		t.Fatalf("unreadable must keep the last view and record why: %+v", tk)
	}
}

func TestSync_ReopenedClearsTheCloseAndItsComment(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{"SEC-4": {Name: "In Progress", Category: "indeterminate"}}}
	prev := platform.TicketRef{Key: "SEC-4", Resolved: true, ResolvedAt: t0, ClosedStillPresent: true, Notified: "still_present"}
	changed, res := Sync(context.Background(), []platform.Action{action("a4", nil, prev)}, trackerOf(f), t0.Add(time.Hour), Options{})
	tk := changed[0].Ticket
	if res.Reopened != 1 || tk.Resolved || tk.ClosedStillPresent || tk.Notified != "" {
		t.Fatalf("a reopened ticket must drop what we said about its close: %+v", tk)
	}
}

func TestSync_FixedIsToldButUnconfirmedIsNot(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{"F": {Category: "indeterminate"}, "U": {Category: "done"}}}
	acts := []platform.Action{
		action("f", &platform.FixVerification{Status: platform.FixStatusFixed, VerifiedAt: t0}, platform.TicketRef{Key: "F"}),
		action("u", &platform.FixVerification{Status: platform.FixStatusRescanUnconfirmed, VerifiedAt: t0}, platform.TicketRef{Key: "U"}),
	}
	_, res := Sync(context.Background(), acts, trackerOf(f), t0, Options{Comments: true})
	if res.Commented != 1 || len(f.comments["U"]) != 0 {
		t.Fatalf("rescan_unconfirmed must never produce a 'fixed' comment: %+v %v", res, f.comments)
	}
	if !strings.Contains(f.comments["F"][0], "can be closed") {
		t.Fatalf("a fix confirmed while the ticket is open should say it can be closed: %v", f.comments["F"])
	}
}

func TestSync_FailedCommentIsRetriedNotMarkedSent(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{"F": {Category: "done", ResolvedAt: t0}}, failPost: true}
	acts := []platform.Action{action("f", &platform.FixVerification{Status: platform.FixStatusFixed, VerifiedAt: t0}, platform.TicketRef{Key: "F"})}
	changed, res := Sync(context.Background(), acts, trackerOf(f), t0, Options{Comments: true})
	if res.CommentFailed != 1 || changed[0].Ticket.Notified != "" || !strings.Contains(changed[0].Ticket.SyncError, "403") {
		t.Fatalf("a comment that failed must not be recorded as sent: %+v", changed[0].Ticket)
	}
}

func TestSync_SkipsSettledAndUnappliedAndBoundsReads(t *testing.T) {
	f := &fakeTracker{status: map[string]connector.IssueStatus{}}
	settledAct := action("s", &platform.FixVerification{Status: platform.FixStatusFixed}, platform.TicketRef{Key: "S", Resolved: true, Notified: "fixed"})
	pending := action("p", nil, platform.TicketRef{Key: "P"})
	pending.Status = platform.ActPendingApproval
	var many []platform.Action
	for i := 0; i < 10; i++ {
		many = append(many, action(string(rune('a'+i)), nil, platform.TicketRef{Key: string(rune('A' + i))}))
	}
	changed, res := Sync(context.Background(), append([]platform.Action{settledAct, pending}, many...), trackerOf(f), t0, Options{MaxReads: 4})
	if res.Read != 4 || len(changed) != 4 {
		t.Fatalf("reads must be bounded and skip settled/unapplied: %+v", res)
	}
}
