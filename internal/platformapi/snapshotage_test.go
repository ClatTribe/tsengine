package platformapi

import (
	"strings"
	"testing"
	"time"
)

// A cloud conclusion drawn from a month-old inventory reads exactly like one drawn from this morning's
// unless the product says otherwise — and the reader cannot tell, because only we recorded when the
// snapshot was taken.

func TestSnapshotAge_RecentSnapshotSaysNothing(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	if note := snapshotAgeNote(now.Add(-2*time.Hour), now); note != "" {
		t.Errorf("a two-hour-old snapshot produced a staleness note: %q", note)
	}
	// Clock skew (a capture stamped slightly in the future) must not produce a nonsense age.
	if note := snapshotAgeNote(now.Add(2*time.Minute), now); note != "" {
		t.Errorf("clock skew produced a note: %q", note)
	}
}

func TestSnapshotAge_OldSnapshotSaysHowOldAndWhatIsMissing(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	note := snapshotAgeNote(now.Add(-30*24*time.Hour), now)
	if note == "" {
		t.Fatal("a month-old inventory produced no staleness note")
	}
	// It has to carry the age, the capture date, and what the reader should do.
	if !strings.Contains(note, "weeks") && !strings.Contains(note, "month") {
		t.Errorf("the note does not say how old: %q", note)
	}
	if !strings.Contains(note, "2026-07-16") {
		t.Errorf("the note does not give the capture date: %q", note)
	}
	if !strings.Contains(strings.ToLower(note), "re-post") {
		t.Errorf("the note does not say how to get a current picture: %q", note)
	}
	// And it must name the consequence, not just the number.
	if !strings.Contains(strings.ToLower(note), "not reflected") {
		t.Errorf("the note does not say what the analysis is missing: %q", note)
	}
}

// A snapshot with no recorded capture time must say the age is UNKNOWN. Computing from the zero time
// would render "56 years ago", which reads as a bug and gets dismissed instead of prompting a refresh.
func TestSnapshotAge_UnknownCaptureTimeSaysUnknown(t *testing.T) {
	note := snapshotAgeNote(time.Time{}, time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	if note == "" {
		t.Fatal("a snapshot with no capture time produced no note")
	}
	low := strings.ToLower(note)
	if !strings.Contains(low, "unknown") {
		t.Errorf("the note does not admit the age is unknown: %q", note)
	}
	for _, absurd := range []string{"years", "1970", "0001"} {
		if strings.Contains(low, absurd) {
			t.Errorf("the note computed an age from the zero time (%q): %q", absurd, note)
		}
	}
}

func TestHumanAge_ReadsTheWaySomeoneWouldSayIt(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Hour, "30 hours"},
		{5 * 24 * time.Hour, "5 days"},
		{21 * 24 * time.Hour, "3 weeks"},
		{120 * 24 * time.Hour, "4 months"},
	} {
		if got := humanAge(tc.d); got != tc.want {
			t.Errorf("humanAge(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
