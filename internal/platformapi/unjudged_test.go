package platformapi

import (
	"strings"
	"testing"
)

// A silent skip reads as a clean bill of health.
//
// Every assessor skips an item it cannot identify, which is right — a finding that cannot name its
// subject is unactionable. But the response then said {"devices": 2, "issues_detected": 0}, which any
// reader takes as "we checked two laptops and they're fine". For disk encryption that is a compliance
// claim, so the silence does not just lose a finding; it manufactures assurance nothing supported.

func TestUnjudgedNote_SilentWhenEverythingWasAssessed(t *testing.T) {
	if got := unjudgedNote(3, 3, "device", "devices", "no name"); got != "" {
		t.Errorf("a fully-assessed batch produced a warning: %q", got)
	}
	if got := unjudgedNote(0, 0, "device", "devices", "no name"); got != "" {
		t.Errorf("an empty batch produced a warning: %q", got)
	}
}

// The note has to carry the numbers. "Some items were skipped" is not checkable; "2 of 2" is.
func TestUnjudgedNote_StatesHowManyOfHowMany(t *testing.T) {
	got := unjudgedNote(5, 3, "device", "devices", "they did not carry a device name")
	if !strings.Contains(got, "2 of 5") {
		t.Errorf("the note does not say how many of how many: %q", got)
	}
	if !strings.Contains(got, "device name") {
		t.Errorf("the note does not say WHY, so nobody can fix their export: %q", got)
	}
	// And it must say plainly that this is not a pass.
	if !strings.Contains(strings.ToLower(got), "not a clean result") {
		t.Errorf("the note does not deny the clean reading: %q", got)
	}
}

// The whole-batch case is the one that actually happened — a field-name mismatch drops everything.
func TestUnjudgedNote_WholeBatchDropped(t *testing.T) {
	got := unjudgedNote(2, 0, "device", "devices", "they did not carry a device name")
	if !strings.Contains(got, "2 of 2") {
		t.Errorf("want 2 of 2, got %q", got)
	}
}

func TestUnjudgedNote_ReadsCorrectlyForOne(t *testing.T) {
	got := unjudgedNote(4, 3, "vendor", "vendors", "they did not carry a vendor name")
	if !strings.Contains(got, "1 of 4 vendor was") {
		t.Errorf("singular phrasing is wrong: %q", got)
	}
}

// A negative can only come from a caller bug (judged > posted); it must not produce a nonsense note.
func TestUnjudgedNote_NeverReportsANegative(t *testing.T) {
	if got := unjudgedNote(2, 5, "device", "devices", "no name"); got != "" {
		t.Errorf("judged > posted produced a note: %q", got)
	}
}

func TestCountNamed_MatchesWhatTheAssessorsAccept(t *testing.T) {
	// The assessors trim before testing for empty, so whitespace is not a name.
	if got := countNamed([]string{"mac-1", "", "   ", "\t", "mac-2"}); got != 2 {
		t.Errorf("countNamed = %d, want 2 (whitespace is not a name — the assessors trim too)", got)
	}
	if got := countNamed(nil); got != 0 {
		t.Errorf("countNamed(nil) = %d, want 0", got)
	}
}
