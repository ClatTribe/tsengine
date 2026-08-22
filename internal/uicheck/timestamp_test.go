package uicheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A ZERO TIMESTAMP IS TRUTHY, so a screen must never decide from a timestamp's presence.
//
// Go's `omitempty` does not omit a zero time.Time — the tag has no effect on a struct — so a field
// the API advertises as optional, and that the TypeScript type declares `field?: string`, arrives
// on every record as "0001-01-01T00:00:00Z". `!!incident.acknowledged_at` is therefore ALWAYS true.
//
// On the incident queue that shipped two false claims at once, both invisible to the compiler:
// every open incident rendered "acknowledged" — which also REPLACES the Acknowledge button, so the
// one action in the alert-response path could not be taken — on a page whose own scorecard read
// "0 acknowledged"; and every incident claimed a CISA deadline had passed.
//
// Producers are being fixed to send nil, but records already stored carry the zero time. The reader
// must not trust presence. `lib/time.ts#hasTime` is the one place that knows this.

func frontendDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "frontend"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); err != nil {
		t.Skipf("frontend not present: %v", err)
	}
	return d
}

func TestHasTimeRejectsTheZeroTimestamp(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(frontendDir(t), "lib", "time.ts"))
	if err != nil {
		t.Fatalf("frontend/lib/time.ts is missing: %v\n\n"+
			"It is the single place that knows a zero timestamp is not a timestamp. Without it "+
			"every screen re-derives that rule, and the ones that forget report a value nobody set.", err)
	}
	src := string(b)
	if !strings.Contains(src, "export function hasTime") {
		t.Error("frontend/lib/time.ts no longer exports hasTime")
	}
	// The guard must reject a value that PARSES but predates the product. Rejecting only absent or
	// unparseable values is the bug: "0001-01-01T00:00:00Z" is both present and perfectly parseable.
	if !strings.Contains(src, "Date.UTC(2000, 0, 1)") {
		t.Error("hasTime no longer bounds timestamps below a plausible floor.\n\n" +
			"An absent/NaN check alone does not catch the zero time, which is the whole case: it is " +
			"a non-empty, valid date string that lands in the year 1.")
	}
}

// acknowledgedAtTruthiness matches a decision made from the mere presence of a *_at timestamp.
// Formatting a timestamp behind a presence check is cosmetic; deciding an incident's STATE from
// one is the defect, so this is scoped to the incident queue where that decision is made.
var truthyTimestamp = regexp.MustCompile(`!![A-Za-z_$][A-Za-z0-9_$.]*_at\b`)

func TestIncidentQueueDoesNotDecideFromTimestampPresence(t *testing.T) {
	p := filepath.Join(frontendDir(t), "app", "(app)", "incidents", "page.tsx")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading the incident queue: %v", err)
	}
	src := string(b)

	if m := truthyTimestamp.FindString(src); m != "" {
		t.Errorf("the incident queue decides from a timestamp's presence: %s\n\n"+
			"A zero timestamp is truthy, so this reads \"never happened\" as \"happened\". Use "+
			"hasTime() from @/lib/time.", m)
	}
	if !strings.Contains(src, "hasTime(i.acknowledged_at)") {
		t.Error("the Acknowledge control no longer reads acknowledgement through hasTime().\n\n" +
			"With a raw truthiness check every open incident renders as acknowledged, and because " +
			"AckButton shows the badge INSTEAD of the button, the incident can never be acknowledged.")
	}
	// The CISA deadline is the same class: a zero time parses to year 1, which is in the past, so
	// an unguarded read reports a federal deadline as already breached.
	if !strings.Contains(src, "BOD_22_01_ISSUED") {
		t.Error("the CISA deadline badge no longer bounds the date it was given.\n\n" +
			"CISA publishes no deadline earlier than the directive itself; anything before that is " +
			"a zero value wearing a date, and rendering it says the customer is already late.")
	}
}
