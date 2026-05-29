package l2

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestShouldCompact(t *testing.T) {
	if !shouldCompact(700, 1000, 0.7) {
		t.Error("700/1000 ≥ 0.7 should compact")
	}
	if shouldCompact(699, 1000, 0.7) {
		t.Error("699/1000 < 0.7 should not compact")
	}
	if shouldCompact(900, 1000, 0) {
		t.Error("fraction 0 disables compaction")
	}
}

func TestCompactHistory_KeepsObjectiveAndTail_DropsMiddle(t *testing.T) {
	// objective + 10 middle turns + tail; keepRecent=4.
	history := []Message{{Role: RoleUser, Content: "OBJECTIVE"}}
	for i := 0; i < 10; i++ {
		history = append(history, Message{Role: RoleAssistant, Content: "mid"})
	}
	history = append(history,
		Message{Role: RoleAssistant, Content: "t1"},
		Message{Role: RoleUser, Content: "t2"},
		Message{Role: RoleAssistant, Content: "t3"},
		Message{Role: RoleUser, Content: "t4"},
	)
	st := &State{Phase: PhaseInvestigate, Findings: []types.Finding{{ID: "f-1", Title: "SQLi"}}}

	out := compactHistory(history, 4, st)

	// objective + 1 summary + 4 tail = 6.
	if len(out) != 6 {
		t.Fatalf("compacted len = %d, want 6", len(out))
	}
	if out[0].Content != "OBJECTIVE" {
		t.Errorf("objective must be preserved as history[0]: %q", out[0].Content)
	}
	if !strings.Contains(out[1].Content, "compacted") || !strings.Contains(out[1].Content, "f-1") {
		t.Errorf("summary should mention compaction + the emitted finding: %q", out[1].Content)
	}
	// Tail preserved verbatim.
	if out[len(out)-1].Content != "t4" {
		t.Errorf("tail end = %q, want t4", out[len(out)-1].Content)
	}
}

func TestCompactHistory_NoOpWhenSmall(t *testing.T) {
	h := []Message{{Role: RoleUser, Content: "o"}, {Role: RoleAssistant, Content: "a"}}
	if got := compactHistory(h, 12, &State{}); len(got) != len(h) {
		t.Errorf("small history should be returned unchanged")
	}
}

func TestCompactHistory_DoesNotOrphanToolResult(t *testing.T) {
	// Tail boundary would land on a RoleTool → must extend back so the tail
	// doesn't start with an orphaned tool_result.
	history := []Message{{Role: RoleUser, Content: "OBJECTIVE"}}
	for i := 0; i < 6; i++ {
		history = append(history, Message{Role: RoleAssistant, Content: "mid"})
	}
	history = append(history,
		Message{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "x", Name: "get_finding"}}},
		Message{Role: RoleTool, ToolCallID: "x", Content: "result"},
		Message{Role: RoleTool, ToolCallID: "y", Content: "result2"},
	)
	out := compactHistory(history, 2, &State{Phase: PhaseTriage})
	// The first tail message must not be an orphaned tool_result.
	for i, m := range out {
		if m.Role == RoleTool && i > 0 && out[i-1].Role == RoleUser && strings.Contains(out[i-1].Content, "compacted") {
			t.Error("tail starts with an orphaned tool_result right after the summary")
		}
	}
}

// End-to-end: a small context window forces the loop to compact mid-run,
// and the run still completes.
func TestAgent_CompactsUnderWindowPressure(t *testing.T) {
	// Each turn reports a big InputTokens so the 0.7 fraction of a 1000
	// window (700) is exceeded → compaction every turn that isn't a no-op.
	big := func(name string) Response {
		r := scriptCall(name, nil, 0.0)
		r.Usage.InputTokens = 900 // > 0.7 * 1000
		return r
	}
	script := []Response{big("advance_phase"), big("advance_phase"), big("advance_phase")}
	for i := 0; i < 15; i++ {
		script = append(script, big("advance_phase")) // no-ops at report → stall
	}
	mc := &MockClient{Window: 1000, Script: script}
	b := DefaultBudget()
	b.MaxIdleTurns = 4
	b.KeepRecentMsgs = 4
	a, _ := New(mc, CoreTools(), b)
	out, err := a.Run(context.Background(), webTarget(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Compactions == 0 {
		t.Error("expected at least one compaction under window pressure")
	}
}
