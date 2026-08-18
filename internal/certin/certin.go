// Package certin implements the CERT-In (Indian Computer Emergency Response Team)
// incident-reporting obligation — the duty an Indian entity is held to that no
// severity-based remediation SLA expresses.
//
// THE OBLIGATION. CERT-In's Directions of 28 April 2022 (No. 20(3)/2022-CERT-In)
// require a covered entity to report specified cyber incidents to CERT-In **within
// six hours of noticing them**. That is a REPORTING deadline, not a fix deadline:
// the clock starts when the incident is detected and is satisfied by NOTIFYING the
// regulator, whether or not the underlying issue is fixed. Missing it is a
// regulatory breach in its own right, which is why it cannot be folded into
// SLAPolicy's ack/resolve clocks — an incident can be well inside its remediation
// SLA and already late to CERT-In.
//
// WHAT IS REPORTABLE. Annexure I of the Directions enumerates the incident types
// that must be reported. This package decides reportability ONLY from what the
// incident's own finding already carries (its CERT-In control annotation, produced
// by the compliance crosswalk) — never from a guess about what an incident "probably
// is". No annotation, no reporting duty asserted (§10). That keeps a false
// regulatory alarm — telling a customer they are late to a regulator when they are
// not — structurally impossible.
//
// DELIBERATELY NOT AUTOMATED: the filing itself. The Directions require a named
// human to submit to CERT-In; this package computes the deadline, the countdown and
// the breach, and prepares the report — a person files it. Same division of labour
// as every other regulatory act in the platform (§18.4).
package certin

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ReportWindow is the CERT-In reporting deadline: six hours from noticing the
// incident (Directions of 28 April 2022, Direction (ii)).
const ReportWindow = 6 * time.Hour

// Framework is the compliance key whose annotation marks a finding as one of the
// Annexure I reportable categories.
const Framework = "certin"

// Status is the reporting position of one incident against the six-hour window.
type Status struct {
	IncidentID string    `json:"incident_id"`
	Title      string    `json:"title"`
	NoticedAt  time.Time `json:"noticed_at"` // when the incident was opened = when we noticed it
	DueAt      time.Time `json:"due_at"`     // NoticedAt + 6h
	Reported   bool      `json:"reported"`   // a human has filed it
	ReportedAt time.Time `json:"reported_at,omitempty"`
	Breached   bool      `json:"breached"` // past due and still not reported
	// Categories are the Annexure I types this incident falls under, taken from the
	// finding's own CERT-In annotation — the evidence for WHY it is reportable.
	Categories []string `json:"categories"`
	// MinutesLeft is negative once the window has closed. Rendered by the UI as the
	// countdown; the six-hour window makes minutes the meaningful unit, not hours.
	MinutesLeft int `json:"minutes_left"`
}

// Reportable reports whether an incident falls under Annexure I, grounded ONLY in the
// CERT-In annotation the compliance crosswalk put on its opening finding. An incident
// with no such annotation carries no reporting duty — absence of evidence is never
// turned into a regulatory obligation.
func Reportable(categories []string) bool { return len(categories) > 0 }

// Evaluate computes the reporting position of one incident. categories comes from the
// opening finding's CERT-In compliance annotation; an empty set means "not reportable"
// and Evaluate returns ok=false so the caller shows nothing rather than a false alarm.
//
// A RESOLVED incident is still reportable: fixing the issue does not retire the duty to
// have told the regulator, and pretending otherwise would let a fast fix hide a missed
// filing. Only an actual filing (reportedAt) stops the clock.
func Evaluate(inc platform.Incident, categories []string, reportedAt time.Time, now time.Time) (Status, bool) {
	if !Reportable(categories) || inc.OpenedAt.IsZero() {
		return Status{}, false
	}
	due := inc.OpenedAt.Add(ReportWindow)
	st := Status{
		IncidentID: inc.ID, Title: inc.Title,
		NoticedAt: inc.OpenedAt.UTC(), DueAt: due.UTC(),
		Categories: append([]string(nil), categories...),
	}
	if !reportedAt.IsZero() {
		st.Reported, st.ReportedAt = true, reportedAt.UTC()
	}
	st.MinutesLeft = int(due.Sub(now).Round(time.Minute) / time.Minute)
	// Breach is only ever asserted for an UNREPORTED incident past its window. A filed
	// report — even a late one — is a discharged duty, not a standing breach.
	st.Breached = !st.Reported && now.After(due)
	return st, true
}

// Report is the filing prepared for the named human who submits it to CERT-In. It is a
// DRAFT: every field is drawn from the incident and its finding, and the covering
// entity's own details are left to the filer, because inventing them would be putting
// words in a regulated entity's mouth.
type Report struct {
	IncidentID string    `json:"incident_id"`
	NoticedAt  time.Time `json:"noticed_at"`
	DueAt      time.Time `json:"due_at"`
	Categories []string  `json:"categories"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Evidence   string    `json:"evidence"`
	Body       string    `json:"body"`
}

// Prepare builds the draft filing for an incident. Grounded: it states only what the
// incident and its finding establish, and marks unknown fields for the filer rather
// than filling them in.
func Prepare(inc platform.Incident, categories []string, now time.Time) (Report, bool) {
	if !Reportable(categories) {
		return Report{}, false
	}
	due := inc.OpenedAt.Add(ReportWindow).UTC()
	var b strings.Builder
	fmt.Fprintf(&b, "CERT-In INCIDENT REPORT (draft — for submission by a named authorised person)\n\n")
	fmt.Fprintf(&b, "Reporting obligation: Directions of 28 April 2022, Direction (ii) — within six hours of noticing.\n")
	fmt.Fprintf(&b, "Noticed at (UTC): %s\nReport due by (UTC): %s\n\n", inc.OpenedAt.UTC().Format(time.RFC3339), due.Format(time.RFC3339))
	fmt.Fprintf(&b, "Annexure I category:\n")
	for _, c := range categories {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	fmt.Fprintf(&b, "\nIncident: %s\nSeverity: %s\nDetection: automated security assessment (tsengine)\n", inc.Title, inc.Severity)
	if inc.RuleID != "" {
		fmt.Fprintf(&b, "Detection rule: %s\n", inc.RuleID)
	}
	fmt.Fprintf(&b, "\nAffected system/entity: %s\n", nz(inc.Key, "[to be completed by the filer]"))
	fmt.Fprintf(&b, "\nTO BE COMPLETED BY THE FILER (we do not assert these on your behalf):\n")
	fmt.Fprintf(&b, "  - Entity name, sector and CERT-In point of contact\n")
	fmt.Fprintf(&b, "  - Impact assessment and whether personal data was affected (DPDP interaction)\n")
	fmt.Fprintf(&b, "  - Remedial actions taken or planned\n")
	return Report{
		IncidentID: inc.ID, NoticedAt: inc.OpenedAt.UTC(), DueAt: due,
		Categories: append([]string(nil), categories...),
		Title:      inc.Title, Severity: inc.Severity,
		Evidence: inc.FindingID,
		Body:     b.String(),
	}, true
}

func nz(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}
