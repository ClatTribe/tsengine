package webagent

import (
	"context"
	"strings"
	"testing"
)

type emptyDispatcher struct{}

func (emptyDispatcher) RunTool(_ context.Context, _ string, _ map[string]any) (string, error) {
	return "   \n", nil // ran cleanly, produced only whitespace
}

// TestDispatchOSS_EmptyOutputIsHonest: a tool that runs cleanly but returns NO output must NOT read as
// a bare empty "result:" — that would let the agent wrongly conclude the target is clean. dispatch_oss
// must replace an empty result with an explicit, tool-specific note (§10). Grounded: a live nuclei
// dispatch returned empty because the target's flaw was a CUSTOM app vuln with no public template.
func TestDispatchOSS_EmptyOutputIsHonest(t *testing.T) {
	// nuclei-specific message: must warn that empty ≠ secure.
	cc := &Context{ctx: context.Background(), dispatcher: emptyDispatcher{}}
	out := tDispatchOSS(cc, map[string]any{"tool": "nuclei", "args": map[string]any{"url": "http://t/"}})
	if strings.TrimSpace(strings.SplitN(out, "result:\n", 2)[1]) == "" {
		t.Fatalf("empty nuclei output left a bare result: %q", out)
	}
	if !strings.Contains(out, "template") || !strings.Contains(strings.ToLower(out), "not mean") {
		t.Errorf("nuclei empty note should explain no-template ≠ secure: %s", out)
	}

	// generic tool: a clear "ran but no output" note, not blank.
	cc2 := &Context{ctx: context.Background(), dispatcher: emptyDispatcher{}}
	out2 := tDispatchOSS(cc2, map[string]any{"tool": "hydra", "args": map[string]any{"target": "t"}})
	if !strings.Contains(out2, "no output") {
		t.Errorf("generic empty note missing: %s", out2)
	}

	// a NON-empty result is passed through unchanged (no false rewrite).
	cc3 := &Context{ctx: context.Background(), dispatcher: &capturingDispatcher{}}
	out3 := tDispatchOSS(cc3, map[string]any{"tool": "sqlmap", "args": map[string]any{"url": "http://t/"}})
	if !strings.Contains(out3, "ok") {
		t.Errorf("non-empty output must pass through: %s", out3)
	}
}
