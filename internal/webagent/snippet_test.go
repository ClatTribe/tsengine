package webagent

import (
	"strings"
	"testing"
)

// TestLLMSnippet_ShowsMidBodyData: the body snippet SHOWN TO THE AGENT must not elide the DATA region
// of a normal-sized page. The deterministic DISCOVERED line extracts SURFACE (endpoints/params) but not
// DATA VALUES (object ids in a table, record fields, a secret/flag rendered in the page). For the whole
// "read the data to exploit it" class — IDOR, enumeration, info-disclosure, LFI file reads, SSTI output —
// the agent must SEE those values to pick its next action. At llmSnippetCap=2048 a ~6KB page's middle
// (where a data table lives) was elided, so the agent was blind to the very ids it needed to enumerate.
// This asserts a realistic mid-body datum survives into the LLM snippet (grounded on a live IDOR run).
func TestLLMSnippet_ShowsMidBodyData(t *testing.T) {
	var b strings.Builder
	b.WriteString("<html><head>")
	b.WriteString(strings.Repeat("<link rel=stylesheet href=/x>", 55)) // ~1.6KB head, like a real page's <head>
	b.WriteString("</head><body><table>\n")
	b.WriteString("<tr><td>Order</td><td><a href=\"/order/30042\">receipt</a></td></tr>\n") // the object id the agent must read
	b.WriteString(strings.Repeat("<tr><td>row</td><td>filler</td></tr>\n", 120))            // pushes total > cap
	b.WriteString("</body></html>")
	body := b.String()
	if len(body) < 5000 || len(body) > 9000 {
		t.Fatalf("fixture must be a normal-page size (5-9KB) to model the real case; got %d", len(body))
	}
	snip := headTail(body, llmSnippetCap-llmSnippetTail, llmSnippetTail)
	if !strings.Contains(snip, "/order/30042") {
		t.Errorf("LLM snippet elided the mid-body object id an IDOR/enumeration agent needs "+
			"(llmSnippetCap=%d, body=%d bytes, snippet=%d bytes) — the agent is blind to the data it must exploit",
			llmSnippetCap, len(body), len(snip))
	}
}
