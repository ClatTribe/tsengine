package uicheck

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/agentmemory"
)

// The memory page shows exactly what the AI engineer is told. A kind the builder emits and the page has no
// section for would be told to the agent and hidden from the customer — memory they cannot see is memory
// they cannot correct. FAILS rather than skips when the file moves (§14.2 rule 6).
func TestMemoryPageShowsEveryKindTheAgentIsTold(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "memory", "page.tsx"))
	for _, k := range []string{agentmemory.KindNote, agentmemory.KindOwner, agentmemory.KindOutOfScope,
		agentmemory.KindDecision, agentmemory.KindDeclinedFix, agentmemory.KindExplain} {
		if !strings.Contains(src, `kind: "`+k+`"`) {
			t.Errorf("the memory page has no section for %q, which the agent is told", k)
		}
	}
	if !strings.Contains(src, "It is context, not evidence") {
		t.Error("the page must say the memory is context, not evidence")
	}
	if !strings.Contains(src, "mem.omitted") {
		t.Error("what the caps leave out must be stated, or the page reads as the complete list")
	}
}
