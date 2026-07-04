package webagent

import (
	"strings"
	"testing"
)

// TestRenderTranscript_LatestObservationFull: the agent decides its next action from the transcript in
// the prompt. Every entry used to be capped at 1800 chars (head-only), so even the CURRENT observation —
// the page the agent must act on — was truncated, and data past ~1800 bytes (an object-id table, a
// record, a rendered secret) was invisible. Grounded on a live IDOR run where the /orders id table sat
// past the cap. The latest entry must be shown in full (up to latestEntryCap); older entries stay
// compacted so the prompt stays bounded.
func TestRenderTranscript_LatestObservationFull(t *testing.T) {
	// latest observation: ~4KB of markup, then the datum the agent needs, well past the old 1800 cap.
	latest := "ACTION send_request({\"url\":\"/orders\"})\nOBSERVATION: t-005 status=200\n" +
		strings.Repeat("<tr><td>filler</td></tr>", 170) + // ~4KB, pushes the datum past 1800
		"<a href=\"/order/30042\">receipt</a></body>"
	old := "ACTION send_request({\"url\":\"/\"})\nOBSERVATION: t-001 status=200\n" + strings.Repeat("x", 4000)

	out := renderTranscript([]string{old, latest})

	if !strings.Contains(out, "/order/30042") {
		t.Errorf("the LATEST observation's data (past the old 1800 cap) must be visible — the agent is "+
			"blind to the current page it must act on (latestEntryCap=%d)", latestEntryCap)
	}
	// history stays bounded: the old entry is compacted, not shown whole.
	if strings.Count(out, "x") > histEntryCap {
		t.Errorf("old entry not compacted (%d x's) — history must stay bounded", strings.Count(out, "x"))
	}
	// prompt stays bounded overall.
	if len(out) > histEntryCap+latestEntryCap+64 {
		t.Errorf("rendered transcript exceeded the bound: %d bytes", len(out))
	}
}

// TestRenderTranscript_SingleEntryFull: with one turn, that turn is the latest and shown in full.
func TestRenderTranscript_SingleEntryFull(t *testing.T) {
	e := "OBSERVATION: " + strings.Repeat("y", 3000) + "flag_here"
	out := renderTranscript([]string{e})
	if !strings.Contains(out, "flag_here") {
		t.Error("a single (latest) entry must be shown in full")
	}
}
