package webagent

import (
	"context"
	"strings"
	"testing"
)

// TestDispatchOSS_KeepsArtifactAtBottomOfLongDump: a long sqlmap/hydra/ffuf-style dump whose EXTRACTED
// artifact (a cracked credential, a dumped table cell, a discovered flag) lands at the very END — past
// both llmSnippetCap and evidenceBodyCap — must still be visible in the LLM result AND recorded in the
// evidence Turn. The #807 head+tail fix was applied to send_request but NOT to the dispatch_oss handler,
// which head-truncated: the agent never saw the data it extracted, and the signed evidence bundle was
// missing the proof. sqlmap's output ordering puts the extracted values near the end, so this is the
// common case for the whole reason dispatch_oss(sqlmap) exists.
func TestDispatchOSS_KeepsArtifactAtBottomOfLongDump(t *testing.T) {
	artifact := "flag{deep-extraction-at-the-tail}"
	// exceed evidenceBodyCap (16384) so BOTH caps would head-truncate the tail
	long := strings.Repeat("Database: app\nTable: users\n[*] row dumped\n", 700) + "\n[*] extracted secret: " + artifact
	if len(long) <= evidenceBodyCap {
		t.Fatalf("test setup: dump must exceed evidenceBodyCap (%d), got %d", evidenceBodyCap, len(long))
	}

	fd := &fakeDispatcher{out: long}
	cc := &Context{ctx: context.Background(), dispatcher: fd}
	out := tDispatchOSS(cc, map[string]any{"tool": "sqlmap", "args": map[string]any{"url": "http://t/x?id=1"}})

	if !strings.Contains(out, artifact) {
		t.Errorf("LLM-facing dispatch_oss result dropped the tail artifact — the agent never sees the extracted data")
	}
	if len(cc.History) != 1 {
		t.Fatalf("expected one evidence Turn, got %d", len(cc.History))
	}
	if !strings.Contains(cc.History[0].RespSnippet, artifact) {
		t.Errorf("evidence Turn dropped the tail artifact — the signed evidence bundle is missing the proof")
	}
}
