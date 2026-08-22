package platform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An incident with no CISA deadline must not SERIALIZE one.
//
// `KEVDueAt` was a time.Time tagged `json:"kev_due_at,omitempty"`, and omitempty has no effect on
// a struct — so every incident shipped `"kev_due_at":"0001-01-01T00:00:00Z"`. The frontend guard
// was written against the contract the tag advertises (`if (!i.kev_due_at) return null`), which a
// non-empty string passes; the queue then told the customer a CISA federal remediation deadline
// had PASSED, on incidents with no CVE behind them at all.
//
// This asserts the WIRE, not the field's Go type, because the wire is what the claim is made on.
func TestIncidentWithNoKEVDeadlineOmitsIt(t *testing.T) {
	b, err := json.Marshal(Incident{ID: "inc-1", Severity: "high", Status: IncidentOpen})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "kev_due_at") {
		t.Errorf("an incident with no CISA deadline serialized one:\n%s\n\n"+
			"`omitempty` does not omit a zero time.Time. A consumer reading this field's PRESENCE "+
			"as \"there is a deadline\" — which is what the tag promises — will report a federal "+
			"remediation deadline nobody set, and that it has already passed.", b)
	}
}

// The mirror: a real deadline must survive. A fix that satisfied the test above by dropping the
// field entirely would pass it and silently delete the signal, so both directions are pinned.
func TestIncidentWithAKEVDeadlineKeepsIt(t *testing.T) {
	due := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	b, err := json.Marshal(Incident{ID: "inc-1", Severity: "high", Status: IncidentOpen, KEV: true, KEVDueAt: &due})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"kev_due_at":"2026-03-01T00:00:00Z"`) {
		t.Errorf("a real CISA deadline did not survive marshalling:\n%s", b)
	}
}

// The full wire contract for an incident whose events have not happened: none of the
// "it happened at" timestamps may appear at all.
func TestIncidentOmitsEveryUnsetTimestamp(t *testing.T) {
	// OpenedAt is set because every real incident has one: `opened_at` carries no omitempty, and
	// is REQUIRED rather than optional — an incident that was never opened does not exist. The
	// distinction is the point of this test: a required timestamp is always present, an optional
	// one must be absent until the event it records actually happens.
	b, err := json.Marshal(Incident{ID: "inc-1", Severity: "high", Status: IncidentOpen,
		OpenedAt: time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"resolved_at", "acknowledged_at", "last_escalated_at", "certin_reported_at", "kev_due_at"} {
		if strings.Contains(string(b), k) {
			t.Errorf("%q serialized on an incident where it never happened:\n%s", k, b)
		}
	}
	if strings.Contains(string(b), "0001-01-01") {
		t.Errorf("a zero timestamp reached the wire:\n%s", b)
	}
}

// Set timestamps must survive — a "fix" that omitted them unconditionally would pass the test
// above while deleting the data, so both directions are pinned.
func TestIncidentKeepsTimestampsThatHappened(t *testing.T) {
	at := time.Date(2026, 5, 4, 9, 30, 0, 0, time.UTC)
	b, err := json.Marshal(Incident{
		ID: "inc-1", Severity: "high", Status: IncidentResolved,
		ResolvedAt: at, AcknowledgedAt: at, LastEscalatedAt: at, CertInReportedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"resolved_at", "acknowledged_at", "last_escalated_at", "certin_reported_at"} {
		if !strings.Contains(string(b), `"`+k+`":"2026-05-04T09:30:00Z"`) {
			t.Errorf("%q did not survive marshalling:\n%s", k, b)
		}
	}
}

// THE CASE THE FIELD TYPES ALONE CANNOT REACH: a record already persisted with the zero
// timestamps. It unmarshals into zero values (and, for kev_due_at, a non-nil pointer TO a zero
// time), so without normalising at marshal time the lie is simply re-emitted for the life of the
// record. This is not hypothetical — it is what the live demo store held.
func TestStoredZeroTimestampsAreNotReEmitted(t *testing.T) {
	const legacy = `{"id":"inc-1","severity":"high","status":"open","opened_at":"2026-05-01T08:00:00Z",` +
		`"resolved_at":"0001-01-01T00:00:00Z","acknowledged_at":"0001-01-01T00:00:00Z",` +
		`"last_escalated_at":"0001-01-01T00:00:00Z","certin_reported_at":"0001-01-01T00:00:00Z",` +
		`"kev_due_at":"0001-01-01T00:00:00Z"}`
	var inc Incident
	if err := json.Unmarshal([]byte(legacy), &inc); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "0001-01-01") {
		t.Errorf("a stored zero timestamp was re-emitted verbatim:\n%s\n\n"+
			"Changing the Go field types does not reach records already written. Every consumer of "+
			"this record keeps seeing an event that never happened, for the life of the record.", b)
	}
}
