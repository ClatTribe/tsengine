// Package identitylog reads an identity provider's AUDIT LOG and normalizes it into the events
// internal/identitythreat detects over.
//
// THE GAP THIS CLOSES. The ITDR detector (nine rules: password spray, impossible travel, MFA fatigue,
// MFA-removed-then-access, privileged grant, …) has existed for months and nothing fed it: the only
// door was POST /v1/identity/events, a customer-built pusher that no customer built. So the rules
// were execution-proven in tests and silent in production — the built-but-unwired shape, one level
// up from a handler with no caller, because here the CALLER existed and the DATA did not.
//
// Three providers, each reading the log its IdP already keeps, through the connection the tenant
// already onboarded (no new credential — the operate fetchers use the same token):
//
//   - Okta System Log      GET /api/v1/logs?since=…                       (Link rel="next" paging)
//   - Microsoft Entra      GET /v1.0/auditLogs/signIns + /directoryAudits (@odata.nextLink paging)
//   - Google Workspace     GET /admin/reports/v1/activity/users/all/applications/{login,admin}
//
// THE HONESTY RULES, because a detector fed a partial log is worse than one fed nothing:
//
//   - A provider event we do not map is COUNTED (Report.Unmapped) and never guessed at. A sign-in
//     failure whose reason we cannot classify is still a failure; an event type we have never seen
//     is nothing, and it is reported as nothing rather than silently becoming a login.
//   - What the provider's log cannot say is DECLARED (Report.ChecksNotRun). Google's login events
//     carry no country, so impossible-travel cannot be evaluated from them — the report says so
//     rather than letting a quiet rule read as a clean one.
//   - A page that cannot be decoded is an ERROR, not an empty window. A 2xx that is a login page
//     (an expired token served as HTML) would otherwise read as "no sign-ins", which on a detector
//     is "no attack".
//   - The window is bounded (Window) and overlaps the previous read (Overlap) so a slow provider
//     never loses an event on the boundary; events are deduplicated by the provider's own id.
//
// Read-only by construction: every request is a GET, and the scopes are the audit-log READ scopes
// (okta.logs.read / AuditLog.Read.All / admin.reports.audit.readonly).
package identitylog

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/identitythreat"
)

// Fetcher reads one provider's audit log from `since` to now.
type Fetcher interface {
	Fetch(ctx context.Context, token string, since time.Time) (Report, error)
}

// Report is what one read produced and what it could not.
type Report struct {
	Provider string    `json:"provider"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
	// Fetched is how many provider records were read; Events is how many became detector events.
	Fetched int                    `json:"fetched"`
	Events  []identitythreat.Event `json:"events"`
	// Unmapped counts provider event types we read and did not translate — named so a growing
	// number is visible rather than a silently shrinking signal.
	Unmapped map[string]int `json:"unmapped,omitempty"`
	// ChecksNotRun names detector rules this provider's log cannot feed, and why.
	ChecksNotRun map[string]string `json:"checks_not_run,omitempty"`
}

// Window is how far back a read goes when there is no cursor, and the cap on how far back a cursor
// may reach: a detector over a month of sign-ins would be slow and would re-raise month-old findings.
const Window = 24 * time.Hour

// Overlap is re-read on every pass so an event that landed on the boundary between two reads is
// never lost; duplicates are removed by the provider's own event id.
const Overlap = time.Hour

// SinceFor turns a stored cursor into the read boundary: the cursor minus the overlap, floored at
// now-Window, and Window ago when there is no cursor at all.
func SinceFor(cursor, now time.Time) time.Time {
	floor := now.Add(-Window)
	if cursor.IsZero() {
		return floor
	}
	s := cursor.Add(-Overlap)
	if s.Before(floor) {
		return floor
	}
	return s
}

// Merge concatenates reports' events, drops duplicates by id, and returns them oldest first — the
// order the detector's windowed rules assume.
func Merge(reports ...Report) []identitythreat.Event {
	seen := map[string]bool{}
	var out []identitythreat.Event
	for _, r := range reports {
		for _, e := range r.Events {
			key := r.Provider + "|" + e.ID
			if e.ID == "" || !seen[key] {
				seen[key] = true
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// Latest is the newest event time in a report, for advancing the cursor. Zero when nothing was read,
// so a failed or empty read never moves the cursor forward past events that were not seen.
func Latest(r Report) time.Time {
	var t time.Time
	for _, e := range r.Events {
		if e.Time.After(t) {
			t = e.Time
		}
	}
	return t
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// isAdminRole is the one heuristic in this package, and it is deliberately loose in the SAFE
// direction: a role whose name says admin is flagged privileged so the privileged_grant rule fires;
// a custom role named otherwise is not, and a missed escalation is a known limit we would rather have
// than a spray of false privileged grants.
func isAdminRole(name string) bool {
	n := lower(name)
	return strings.Contains(n, "admin") || strings.Contains(n, "super")
}
