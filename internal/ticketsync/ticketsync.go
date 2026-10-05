// Package ticketsync is the read-back half of ticket delivery: what the customer's tracker says about
// the tickets we filed, set beside what our own re-test says about the finding.
//
// WHY. A remediation delivered as a ticket used to END at "filed" — the filer even discarded the
// created issue's key. So the most common way a remediation quietly fails was invisible: someone moves
// the ticket to Done without fixing the thing, or closes it as Won't Do, and the product carries on
// believing the work is in flight. Fix verification (internal/retest) already re-tests every applied
// action on each authoritative pass; what it could not do is say "the ticket was closed AND the finding
// is still there", which is the sentence a security lead most needs and the one nobody else in the loop
// is placed to say.
//
// TWO VERDICTS, NEVER MERGED. The tracker's (a person moved the ticket to a done state) and ours (the
// action's Verification, from a re-test). A closed ticket does not mark anything fixed here — it is a
// claim, and closure comes only from retest.Verify / ApplyReattack, unchanged. This package records the
// tracker's view and the DISAGREEMENT, and writes our verdict back to the ticket as a comment, so the
// people working in Jira learn it without opening our console.
//
// RULES, each a refusal:
//   - The tracker's CATEGORY decides "done", never the status name. Names are per-workflow ("Shipped",
//     "QA passed"); Jira's statusCategory key is one of three fixed values on every site.
//   - A ticket we cannot read is NOT an open ticket. The read error is recorded and the previous view
//     kept, so a revoked token never renders as "still in progress".
//   - The disagreement only counts a re-test made AFTER the ticket was resolved. A still_present verdict
//     from before the close says nothing about whether the close was premature.
//   - A comment, never a transition: reopening someone's ticket is a decision about their process.
//   - Each outcome is posted once (TicketRef.Notified), and a "rescan_unconfirmed" verdict never produces
//     a "fixed" comment — the comment carries exactly the strength of the evidence behind it.
package ticketsync

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Tracker reads a delivered ticket back and comments on it (satisfied by *connector.Jira, and by what
// remediate.TenantFiler.TrackerFor returns). Declared here rather than imported from remediate so the
// runner can depend on this package — remediate already imports runner.
type Tracker interface {
	TicketStatus(ctx context.Context, key string) (connector.IssueStatus, error)
	AddComment(ctx context.Context, key, text string) error
}

// TrackerFor resolves the tracker holding a ticket, with the credentials that filed it.
type TrackerFor func(ctx context.Context, tenantID string, ref platform.TicketRef) (Tracker, error)

// Options bound one sync.
type Options struct {
	// MaxReads caps tracker reads per call (default 50), oldest-synced first, so a tenant with hundreds of
	// tickets costs a bounded number of API calls per pass and every ticket is reached in turn.
	MaxReads int
	// Comments enables the write-back. Off for callers that must not write (the kill-switch is the
	// caller's to honour; this package does not read tenant state).
	Comments bool
}

// Result is what one sync did — counts, so a caller can log it and a test can assert it.
type Result struct {
	Read               int `json:"read"`
	ReadFailed         int `json:"read_failed"`
	NewlyResolved      int `json:"newly_resolved"`
	Reopened           int `json:"reopened"`
	ClosedStillPresent int `json:"closed_still_present"`
	Commented          int `json:"commented"`
	CommentFailed      int `json:"comment_failed"`
}

// Sync reads the tracker for every eligible ticket, records its view, computes the disagreement and
// (optionally) comments our verdict back. It returns only the actions it CHANGED, for the caller to
// persist.
func Sync(ctx context.Context, acts []platform.Action, trackerFor TrackerFor, now time.Time, opts Options) ([]platform.Action, Result) {
	if opts.MaxReads <= 0 {
		opts.MaxReads = 50
	}
	var res Result
	var due []platform.Action
	for _, a := range acts {
		if a.Ticket == nil || a.Ticket.Key == "" || a.Status != platform.ActApplied {
			continue
		}
		if settled(a) {
			continue // closed, re-tested fixed, and already told — nothing left to learn or say
		}
		due = append(due, a)
	}
	// Oldest-synced first: a bounded pass must reach every ticket eventually, not the same 50 forever.
	sort.SliceStable(due, func(i, j int) bool { return due[i].Ticket.LastSyncedAt.Before(due[j].Ticket.LastSyncedAt) })
	if len(due) > opts.MaxReads {
		due = due[:opts.MaxReads]
	}

	var changed []platform.Action
	for _, a := range due {
		t := *a.Ticket // copy: the caller's slice is not mutated
		tr, err := trackerFor(ctx, a.TenantID, t)
		if err != nil {
			res.ReadFailed++
			t.SyncError = bounded(err.Error())
			a.Ticket = &t
			changed = append(changed, a)
			continue
		}
		st, err := tr.TicketStatus(ctx, t.Key)
		if err != nil {
			res.ReadFailed++
			t.SyncError = bounded(err.Error()) // keep the previous view: unreadable is not "open"
			a.Ticket = &t
			changed = append(changed, a)
			continue
		}
		res.Read++
		t.SyncError = ""
		t.LastSyncedAt = now
		t.Status, t.StatusCategory = st.Name, st.Category
		done := st.Category == "done"
		switch {
		case done && !t.Resolved:
			res.NewlyResolved++
			t.Resolved = true
			t.ResolvedAt = st.ResolvedAt
			if t.ResolvedAt.IsZero() {
				t.ResolvedAt = now // the tracker did not say when; we first saw it done now
			}
		case !done && t.Resolved:
			// Reopened in the tracker. Whatever we said about the close no longer stands.
			res.Reopened++
			t.Resolved, t.ResolvedAt, t.ClosedStillPresent = false, time.Time{}, false
			if t.Notified == "still_present" {
				t.Notified = ""
			}
		}
		t.ClosedStillPresent = closedStillPresent(t, a.Verification)
		if t.ClosedStillPresent {
			res.ClosedStillPresent++
		}

		if opts.Comments {
			if outcome, text := commentFor(t, a); outcome != "" {
				if err := tr.AddComment(ctx, t.Key, text); err != nil {
					res.CommentFailed++
					t.SyncError = bounded("comment: " + err.Error())
				} else {
					res.Commented++
					t.Notified = outcome
				}
			}
		}
		a.Ticket = &t
		changed = append(changed, a)
	}
	return changed, res
}

// settled: nothing more can change. A ticket that is closed AND re-tested fixed AND already told.
func settled(a platform.Action) bool {
	t := a.Ticket
	return t.Resolved && t.Notified == "fixed" && a.Verification != nil && a.Verification.Status == platform.FixStatusFixed
}

// closedStillPresent: the tracker says done AND a re-test made after that still finds the issue.
func closedStillPresent(t platform.TicketRef, v *platform.FixVerification) bool {
	if !t.Resolved || v == nil || v.Status != platform.FixStatusStillPresent {
		return false
	}
	return !v.VerifiedAt.Before(t.ResolvedAt)
}

// commentFor returns the outcome to post and its text, or "" when there is nothing new to say.
func commentFor(t platform.TicketRef, a platform.Action) (string, string) {
	v := a.Verification
	switch {
	case t.ClosedStillPresent && t.Notified != "still_present":
		return "still_present", fmt.Sprintf("TensorShield re-tested after this ticket was closed, and the issue is STILL "+
			"PRESENT (re-test %s: %s). The ticket is marked %q, but the finding it was raised for has not gone away. "+
			"This comment does not reopen the ticket; whether to is your call.",
			v.VerifiedAt.UTC().Format("2006-01-02 15:04 UTC"), nz(v.Evidence, strings.Join(v.StillPresent, ", ")), t.Status)
	case v != nil && v.Status == platform.FixStatusFixed && t.Notified != "fixed":
		msg := fmt.Sprintf("TensorShield re-tested this and the issue is no longer present (re-test %s: %s).",
			v.VerifiedAt.UTC().Format("2006-01-02 15:04 UTC"), nz(v.Evidence, "confirmed gone"))
		if !t.Resolved {
			msg += " This ticket is still open; it can be closed when your team is satisfied."
		}
		return "fixed", msg
	}
	// rescan_unconfirmed and no verdict yet: say nothing. A comment saying "fixed" on evidence we know
	// has failed for this class would be the false all-clear in someone else's tool.
	return "", ""
}

func bounded(s string) string {
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
