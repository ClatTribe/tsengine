package webagent

import (
	"strings"
	"testing"
)

// TestHeadTail_KeepsBottomOfPage: the whole point — a result at the BOTTOM of a big body stays
// visible. Regression for a real miss: a client-side-auth-bypass bench returned the flag AFTER a
// ~2KB inline <style> block, and pure head-truncation showed only the login form, so the agent
// executed the winning POST but never saw the flag.
func TestHeadTail_KeepsBottomOfPage(t *testing.T) {
	big := strings.Repeat("<style>.x{color:red}</style>", 200) // ~5.6KB of head noise
	body := "<title>Login</title>" + big + "Congratulations, here is the flag: flag{bottom-of-page}</body>"

	out := headTail(body, llmSnippetCap-llmSnippetTail, llmSnippetTail)
	if !strings.Contains(out, "flag{bottom-of-page}") {
		t.Fatalf("head+tail dropped the bottom-of-page flag: ...%s", out[len(out)-120:])
	}
	if !strings.Contains(out, "<title>Login</title>") {
		t.Errorf("head+tail dropped the top-of-page context: %s", out[:120])
	}
	if !strings.Contains(out, "bytes elided") {
		t.Errorf("expected an elision marker: %s", out)
	}
	// budget: the kept content is head+tail plus the short marker, not the whole 5.6KB body.
	if len(out) > llmSnippetCap+64 {
		t.Errorf("head+tail exceeded the budget: %d bytes", len(out))
	}
}

// TestHeadTail_ShortBodyUntouched: a body within budget is returned verbatim (no marker, no loss).
func TestHeadTail_ShortBodyUntouched(t *testing.T) {
	body := "small response with flag{short}"
	out := headTail(body, llmSnippetCap-llmSnippetTail, llmSnippetTail)
	if out != body {
		t.Fatalf("short body was altered: %q", out)
	}
}

// TestHeadTail_ExactBoundary: a body exactly at head+tail is returned whole (no off-by-one elision).
func TestHeadTail_ExactBoundary(t *testing.T) {
	body := strings.Repeat("a", llmSnippetCap) // head+tail == llmSnippetCap
	out := headTail(body, llmSnippetCap-llmSnippetTail, llmSnippetTail)
	if out != body {
		t.Errorf("body at the exact boundary should be untouched (len %d -> %d)", len(body), len(out))
	}
}
