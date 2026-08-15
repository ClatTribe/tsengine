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

// ── "YOU SENT NOTHING" IS ALSO A FACT ────────────────────────────────────────────────────────────

// unjudgedNote answers "you sent 12 and we could read 9". It is silent on an empty batch, correctly:
// nothing was skipped. But every ingest adopted only that note, so posting an empty list returned
// {"devices": 0, "issues_detected": 0} with no comment — indistinguishable from a fleet that was
// examined and came back clean. A collector that ran and produced nothing looks exactly like this.
//
// Found by driving all nine ingests with an empty payload: five reported zero findings and said
// nothing about having assessed nothing.

func TestNoInputNote_EmptySubmissionSaysSo(t *testing.T) {
	got := noInputNote(0, "devices")
	if got == "" {
		t.Fatal("an empty submission produced no note — \"0 devices, 0 issues\" reads as a clean fleet")
	}
	if !strings.Contains(got, "not a clean result") {
		t.Errorf("the note does not say the zero means nothing: %q", got)
	}
}

// A non-empty submission gets no empty-note — that is unjudgedNote's job, and duplicating it would
// make every response carry two sentences about the same batch.
func TestNoInputNote_SilentWhenSomethingWasSent(t *testing.T) {
	if got := noInputNote(3, "devices"); got != "" {
		t.Errorf("a submission with 3 devices produced an empty-batch note: %q", got)
	}
}

// The composer carries BOTH facts and keeps them distinct: nothing sent, and some of what was sent
// unreadable. They are different sentences because they send the reader to different places — one to
// the collector, the other to the export's field names.
func TestIngestNotes_CarriesEachFactSeparately(t *testing.T) {
	// nothing sent
	empty := ingestNotes(0, 0, "vendor", "vendors", "they did not carry a vendor name")
	if len(empty) != 1 || !strings.Contains(empty[0], "No vendors were in this submission") {
		t.Errorf("empty batch notes = %v", empty)
	}
	// sent, partially unreadable
	partial := ingestNotes(5, 3, "vendor", "vendors", "they did not carry a vendor name")
	if len(partial) != 1 || !strings.Contains(partial[0], "2 of 5") {
		t.Errorf("partial batch notes = %v", partial)
	}
	// fully assessed → nothing to disclose, so no note at all
	if full := ingestNotes(4, 4, "vendor", "vendors", "x"); len(full) != 0 {
		t.Errorf("a fully-assessed batch produced notes: %v", full)
	}
}
