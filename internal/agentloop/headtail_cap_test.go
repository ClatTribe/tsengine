package agentloop

import (
	"strings"
	"testing"
)

// TestAppendCappedKeepsTheActionableTail covers the context-management contract for transcript
// entries. A tool observation puts its most ACTIONABLE content LAST — the coverage disclosure
// naming which crown jewels nobody examined, the "REMAINING: N still unexamined" countdown, the
// "Consider propose_fix(ai-001)" hint. The old cap kept the head and dropped the tail, so on a
// large account the agent was handed the bulk listing and none of the instructions.
//
// Measured live on a 908-resource account: the prepass observation reached the model as
// "COVERAGE: this prepass is a BOUNDED wor …(truncated)" — the disclosure was computed, rendered,
// and then thrown away one layer later.
func TestAppendCappedKeepsTheActionableTail(t *testing.T) {
	bulk := strings.Repeat("arn:aws:s3:::filler-bucket-0000000000 -> role/filler -> data\n", 200)
	tail := "COVERAGE: 6 crown jewel(s) NOT examined — check each with find_paths(<id>)."
	entry := "ACTION enumerate_attack_paths({})\nOBSERVATION: " + bulk + tail

	got := AppendCapped(nil, entry)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	out := got[0]

	if !strings.Contains(out, "COVERAGE") || !strings.Contains(out, "find_paths") {
		t.Errorf("the ACTIONABLE tail was truncated away — the agent is told to act and never shown\non what. Entry ends with: %q", out[max(0, len(out)-120):])
	}
	if !strings.HasPrefix(out, "ACTION enumerate_attack_paths") {
		t.Errorf("the head must survive too — the agent needs to know which tool produced this: %q", out[:60])
	}
	if len(out) >= len(entry) {
		t.Errorf("a long entry must still be bounded (got %d bytes, original %d)", len(out), len(entry))
	}
	if !strings.Contains(out, "elided") {
		t.Error("an elision must be DECLARED — silently dropping the middle makes a partial observation read as a complete one")
	}
}

// TestAppendCappedLeavesShortEntriesIntact guards the common case: most observations are small and
// must not be reshaped at all.
func TestAppendCappedLeavesShortEntriesIntact(t *testing.T) {
	entry := "ACTION finish({})\nOBSERVATION: investigation closed."
	got := AppendCapped(nil, entry)
	if got[0] != entry {
		t.Errorf("a short entry was altered:\n want %q\n got  %q", entry, got[0])
	}
}
