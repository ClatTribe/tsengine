package platformapi

import (
	"fmt"
	"time"
)

// snapshotage.go: saying how old the cloud picture is before reasoning over it.
//
// THE GAP. cloudInvestigator loads the tenant's STORED cloud snapshot and hands it to the specialist,
// and never looks at snap.CapturedAt. So a customer who posted an inventory once gets confident
// conclusions about IAM paths and internet exposure weeks later — "this role can reach your database"
// — with nothing indicating the picture is old. The role may have been deleted the same afternoon.
//
// We are not able to fetch live cloud state today (the live describe-* fetcher is the credential-gated
// half), which makes this worse rather than better: the whole product runs on a snapshot whose age
// only we can see. An analysis that cannot say how fresh its input is presents a stale conclusion with
// the same confidence as a current one, which is the failure mode this codebase keeps finding.
//
// The age is EXACT — we recorded CapturedAt when we stored it — so this is disclosure, not estimation.

// freshWindow is how recent a snapshot has to be before its age stops being worth mentioning. A cloud
// estate at this segment changes on a deploy cadence, so a picture from this morning is fine and one
// from last month is a different kind of claim.
const freshWindow = 24 * time.Hour

// snapshotAgeNote returns a one-line statement of how old a cloud snapshot is, or "" when it is
// recent enough that the age adds nothing.
//
// A zero CapturedAt means we never recorded when it was taken — say THAT rather than compute a
// nonsense age from the zero time, which would read as "56 years old" and get dismissed as a bug
// instead of prompting a refresh.
func snapshotAgeNote(capturedAt, now time.Time) string {
	if capturedAt.IsZero() {
		return "NOTE: this cloud inventory has no capture time recorded, so its age is unknown. " +
			"Re-post the inventory to be sure these conclusions reflect the account as it is now."
	}
	age := now.Sub(capturedAt)
	if age < 0 || age < freshWindow {
		return "" // taken within the day (or clock skew) — the age is not news
	}
	return fmt.Sprintf("NOTE: this analysis is based on a cloud inventory captured %s ago (%s). "+
		"Anything created, deleted or re-permissioned since then is not reflected — re-post the "+
		"inventory for a current picture.",
		humanAge(age), capturedAt.UTC().Format("2006-01-02 15:04 UTC"))
}

// humanAge renders a duration the way someone would say it. Precision beyond this is false comfort:
// what matters is "this morning" versus "last month", not the minute.
func humanAge(d time.Duration) string {
	switch {
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d < 60*24*time.Hour:
		return fmt.Sprintf("%d weeks", int(d.Hours()/(24*7)))
	default:
		return fmt.Sprintf("%d months", int(d.Hours()/(24*30)))
	}
}
