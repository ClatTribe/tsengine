package l2

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestBuildSystemPrompt_ClearsRenderGuardAndDigestsFindings(t *testing.T) {
	l1 := []types.Finding{
		{ID: "f-2", Severity: types.SeverityLow, RuleID: "nuclei::info", Endpoint: "https://x/a", Title: "info"},
		{ID: "f-1", Severity: types.SeverityCritical, RuleID: "sqlmap::sqli", Endpoint: "https://x/p?id=1", Title: "SQLi"},
	}
	p := BuildSystemPrompt(types.Asset{Type: types.AssetWebApplication, Target: "https://x"}, l1)

	// Render guard: a real prompt always clears the floor.
	if len(p) < minSystemPromptBytes {
		t.Fatalf("prompt %d bytes < floor %d", len(p), minSystemPromptBytes)
	}
	// Evidence-only + no-redetect rules present.
	for _, want := range []string{"NOT to detect", "Never invent", "L1 findings (2)"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	// Critical finding digested before the low one (severity-sorted, stable).
	ci := strings.Index(p, "f-1")
	li := strings.Index(p, "f-2")
	if ci < 0 || li < 0 || ci > li {
		t.Errorf("findings should be severity-sorted (critical f-1 before low f-2): ci=%d li=%d", ci, li)
	}
}

func TestBuildSystemPrompt_NoFindings(t *testing.T) {
	p := BuildSystemPrompt(types.Asset{Type: types.AssetDomain, Target: "x.com"}, nil)
	if len(p) < minSystemPromptBytes {
		t.Errorf("empty-findings prompt should still clear the guard")
	}
	if !strings.Contains(p, "none") {
		t.Errorf("should note no L1 findings")
	}
}
