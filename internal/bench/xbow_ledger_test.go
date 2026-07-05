package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAppendXBOWLedger_AppendOnly: the whole point of the ledger — a second run NEVER overwrites the
// first (the ephemeral --out snapshot's fatal flaw). Two appends -> two entries preserved, in order.
func TestAppendXBOWLedger_AppendOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "xbow-ledger.jsonl") // also proves parent-dir creation
	if err := AppendXBOWLedger(path, XBOWLedgerEntry{TS: "2026-07-05T10:00:00Z", ID: "XBEN-009-24", Tags: []string{"ssti"}, Level: 1, Solved: true, EvidenceSHA256: "aaa"}); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := AppendXBOWLedger(path, XBOWLedgerEntry{TS: "2026-07-05T11:00:00Z", ID: "XBEN-037-24", Tags: []string{"command_injection"}, Level: 1, Solved: true, EvidenceSHA256: "bbb"}); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	got, err := LoadXBOWLedger(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("append-only violated: want 2 entries, got %d — the second run overwrote the first", len(got))
	}
	if got[0].ID != "XBEN-009-24" || got[1].ID != "XBEN-037-24" {
		t.Errorf("order/content lost: %+v", got)
	}
	if AppendXBOWLedger(path, XBOWLedgerEntry{ID: ""}) == nil {
		t.Error("an entry with no benchmark id must be rejected (a blank record is not auditable)")
	}
}

// TestLoadXBOWLedger_SkipsCorruptLine: one bad append (a truncated crash-write) must not void the whole
// campaign log — the surviving good lines still load.
func TestLoadXBOWLedger_SkipsCorruptLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	_ = AppendXBOWLedger(path, XBOWLedgerEntry{TS: "2026-07-05T10:00:00Z", ID: "XBEN-001-24", Solved: true})
	// simulate a torn write + a blank line
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("{not valid json\n\n")
	_ = f.Close()
	_ = AppendXBOWLedger(path, XBOWLedgerEntry{TS: "2026-07-05T12:00:00Z", ID: "XBEN-002-24", Solved: false})
	got, err := LoadXBOWLedger(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 valid entries (corrupt+blank skipped), got %d", len(got))
	}
}

// TestSummarizeXBOWLedger_EverSolvedFirstProof: a capture is a proven capability — an id that solved once
// then MISSED on a later flaky run still counts as captured, cited by its FIRST proving run (earliest ts,
// with that run's evidence sha). And a never-solved id is not counted.
func TestSummarizeXBOWLedger_EverSolvedFirstProof(t *testing.T) {
	entries := []XBOWLedgerEntry{
		{TS: "2026-07-05T09:00:00Z", ID: "XBEN-009-24", Tags: []string{"ssti"}, Level: 1, Solved: true, EvidenceSHA256: "first9"},
		{TS: "2026-07-05T15:00:00Z", ID: "XBEN-009-24", Tags: []string{"ssti"}, Level: 1, Solved: false}, // later flaky miss
		{TS: "2026-07-05T10:00:00Z", ID: "XBEN-006-24", Tags: []string{"command_injection"}, Level: 1, Solved: false}, // never solved
		{TS: "2026-07-05T11:00:00Z", ID: "XBEN-037-24", Tags: []string{"command_injection"}, Level: 2, Solved: true, EvidenceSHA256: "first37"},
	}
	s := SummarizeXBOWLedger(entries)
	if len(s.Captured) != 2 {
		t.Fatalf("want 2 distinct captures (009, 037), got %d: %v", len(s.Captured), s.Captured)
	}
	if fc := s.FirstCapture["XBEN-009-24"]; fc.EvidenceSHA256 != "first9" || fc.TS != "2026-07-05T09:00:00Z" {
		t.Errorf("first-proof citation wrong for 009: %+v", fc)
	}
	if s.ByTag["command_injection"] != 1 { // only 037 solved; 006 never did
		t.Errorf("by-class tally wrong: command_injection=%d, want 1", s.ByTag["command_injection"])
	}
	if s.ByLevel[2] != 1 {
		t.Errorf("by-level tally wrong: level2=%d, want 1", s.ByLevel[2])
	}
}

// TestRenderXBOWLedgerMarkdown_ShowsWrittenNumber: the durable scoreboard must state the capture count and
// list each captured benchmark with its class + evidence-sha proof.
func TestRenderXBOWLedgerMarkdown_ShowsWrittenNumber(t *testing.T) {
	md := RenderXBOWLedgerMarkdown([]XBOWLedgerEntry{
		{TS: "2026-07-05T09:00:00Z", ID: "XBEN-009-24", Tags: []string{"ssti"}, Level: 1, Solved: true, EvidenceSHA256: "abcdef0123456789deadbeef"},
	})
	if !strings.Contains(md, "1 distinct benchmarks captured") {
		t.Errorf("headline count missing:\n%s", md)
	}
	if !strings.Contains(md, "XBEN-009-24") || !strings.Contains(md, "ssti") || !strings.Contains(md, "abcdef0123456789") {
		t.Errorf("capture proof row missing id/class/sha:\n%s", md)
	}
}
