package webagent

import (
	"strings"
	"testing"
)

// TestRecordFinding_XXE: an in-band XXE finding grounded by a file_disclosure turn must be RECORDABLE.
// The canonical in-band XXE proof is an external entity reading a local file
// (<!ENTITY x SYSTEM "file:///etc/passwd">) whose content lands in the response — the SAME
// file_disclosure signal path_traversal/lfi already ground on. Before this fix the class had no
// requiredIndicator entry, so tRecord(class="xxe") returned "REJECTED: unknown vuln class" — the agent
// could exploit XXE but not report it (the §10 silent-drop the ssti gap #810 also had).
func TestRecordFinding_XXE(t *testing.T) {
	cc := &Context{}
	cc.turnN = 1
	cc.History = []Turn{{ID: "t-001", Indicators: []string{"file_disclosure"}}}
	out := tRecord(cc, map[string]any{
		"route": "/import", "class": "xxe", "evidence": []any{"t-001"},
		"severity": "high", "rationale": "external entity read /etc/passwd (root:x:0:0 in response)",
	})
	if strings.Contains(out, "REJECTED") {
		t.Fatalf("XXE finding rejected despite a cited file_disclosure turn: %s", out)
	}
	if len(cc.Findings) != 1 || cc.Findings[0].Class != "xxe" {
		t.Fatalf("XXE finding not recorded: %+v", cc.Findings)
	}
}

// TestRecordFinding_XXE_UngroundedRejected: an XXE claim with NO file_disclosure turn cited stays
// rejected — the grounding rigor is unchanged (a class claim alone can't record a finding).
func TestRecordFinding_XXE_UngroundedRejected(t *testing.T) {
	cc := &Context{}
	cc.turnN = 1
	cc.History = []Turn{{ID: "t-001", Indicators: []string{"cookie_set:sid"}}}
	out := tRecord(cc, map[string]any{
		"route": "/import", "class": "xxe", "evidence": []any{"t-001"},
		"severity": "high", "rationale": "claimed XXE, no file content in evidence",
	})
	if !strings.Contains(out, "REJECTED") {
		t.Fatalf("XXE finding recorded without a grounding file_disclosure turn: %s", out)
	}
}
