package platform

import (
	"encoding/json"
	"time"
)

// MarshalJSON makes `omitempty` mean on the wire what it says in the tag.
//
// Go does not omit a zero time.Time for `omitempty` — the option has no effect on a struct — so
// every timestamp on an Incident that records an event which HAS NOT HAPPENED shipped as
// "0001-01-01T00:00:00Z". A consumer reading presence as "it happened" is not making a mistake;
// it is reading the contract the tag advertises. Two shipped at once on the incident queue:
//
//   - acknowledged_at: `!!incident.acknowledged_at` is true for a non-empty string, so every open
//     incident rendered "acknowledged". That badge REPLACES the Acknowledge button, so the one
//     action in the alert-response path could not be taken — on a page whose own SOC scorecard
//     simultaneously read "0 acknowledged".
//   - kev_due_at: a zero time parses to year 1, which is in the past, so the queue reported that a
//     CISA federal remediation deadline had PASSED — on incidents with no CVE behind them at all.
//     Asserting a government deadline nobody set, and that the reader is already late for it, is a
//     §10 grounding failure in its most alarming form.
//
// Doing this at MARSHAL time rather than by changing each field's Go type is deliberate: it also
// heals records ALREADY STORED with the zero value (which unmarshal into a zero time, or into a
// non-nil pointer to one, and would otherwise be re-emitted verbatim), and it needs no change at
// any of the call sites that read these fields with .IsZero(). Round-trip is stable — an absent
// key unmarshals back to the zero value, which is what it meant.
func (i Incident) MarshalJSON() ([]byte, error) {
	type alias Incident // sheds the method set, so this does not recurse
	a := alias(i)
	if a.KEVDueAt != nil && a.KEVDueAt.IsZero() {
		a.KEVDueAt = nil
	}
	return json.Marshal(struct {
		alias
		// Shadowed with pointers so a zero value really is omitted. Each records an event that
		// may never occur; absent is the honest encoding of "it has not".
		ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
		AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
		LastEscalatedAt  *time.Time `json:"last_escalated_at,omitempty"`
		CertInReportedAt *time.Time `json:"certin_reported_at,omitempty"`
	}{
		alias:            a,
		ResolvedAt:       nonZero(a.ResolvedAt),
		AcknowledgedAt:   nonZero(a.AcknowledgedAt),
		LastEscalatedAt:  nonZero(a.LastEscalatedAt),
		CertInReportedAt: nonZero(a.CertInReportedAt),
	})
}

// nonZero returns nil for the zero time so the field is omitted rather than serialized as year 1.
func nonZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
