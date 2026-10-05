package uicheck

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/detect"
)

// Event incidents never close on their own, so the incidents page must offer the close action and must
// know which incidents are events. Its list mirrors detect's; a producer added server-side and not here
// would show an event incident with no hint that only a person can end it. FAILS rather than skips when
// the file moves (§14.2 rule 6).
func TestIncidentCloseActionAndEventListMirror(t *testing.T) {
	src := stripComments(frontendFile(t, "app", "(app)", "incidents", "page.tsx"))
	if !strings.Contains(src, "<ResolveButton id={i.id} event={isEventIncident(i.rule_id)} />") {
		t.Fatal("the incidents page offers no way to close an incident; event incidents would stay open forever")
	}
	for _, p := range detect.EventProducers() {
		if !strings.Contains(src, `p === "`+p+`"`) {
			t.Errorf("isEventIncident does not know %q, which the server treats as an event producer", p)
		}
	}
	if !strings.Contains(src, "i.resolved_by") {
		t.Error("a person's close and a scan's close render identically; resolved_by is never shown")
	}
}
