package cloudagent

import (
	"strings"
	"testing"
)

// TestFinishRequiresFixesButNeverTraps covers the termination contract. The prompt tells the
// agent to "propose_fix each, then finish", but finish closed unconditionally — so a run that
// recorded 7 attack paths and proposed 1 fix ended looking complete (measured: verified_rate
// 0.14). A recorded path with no fix is half a deliverable (§18.4).
//
// The check is BOUNDED at one nudge. That bound is the load-bearing half: an unbounded gate
// would let a model that cannot produce a fix burn its whole turn budget at the door and
// return nothing — strictly worse than closing with the issues it did find.
func TestFinishRequiresFixesButNeverTraps(t *testing.T) {
	t.Run("holds once when issues are unfixed", func(t *testing.T) {
		cc := &Context{Issues: []Issue{{ID: "ai-001"}, {ID: "ai-002", FixKind: "iam_policy"}}}
		out := tFinish(cc, map[string]any{"summary": "done"})
		if cc.Done {
			t.Error("finish closed with an unfixed issue — the run reports as complete when it is not")
		}
		if !strings.Contains(out, "ai-001") {
			t.Errorf("the hold must NAME the unfixed issue so it is actionable, got: %s", out)
		}
		if strings.Contains(out, "ai-002") {
			t.Errorf("a FIXED issue must not be listed as unfixed, got: %s", out)
		}
	})

	t.Run("never traps — the second finish always closes", func(t *testing.T) {
		cc := &Context{Issues: []Issue{{ID: "ai-001"}}}
		_ = tFinish(cc, map[string]any{"summary": "first"})
		out := tFinish(cc, map[string]any{"summary": "second"})
		if !cc.Done {
			t.Fatal("finish held a SECOND time — an agent that cannot produce a fix would burn its whole budget at the door and return nothing")
		}
		if cc.Summary != "second" {
			t.Errorf("the closing summary was dropped, got %q", cc.Summary)
		}
		if !strings.Contains(out, "closed") {
			t.Errorf("expected a close confirmation, got: %s", out)
		}
	})

	t.Run("closes immediately when every issue is fixed", func(t *testing.T) {
		cc := &Context{Issues: []Issue{{ID: "ai-001", FixKind: "iam_policy"}}}
		if out := tFinish(cc, map[string]any{"summary": "clean"}); !cc.Done {
			t.Errorf("a fully-remediated run must close on the FIRST finish — an extra round-trip is pure cost: %s", out)
		}
	})

	t.Run("closes immediately when nothing was recorded", func(t *testing.T) {
		cc := &Context{}
		if out := tFinish(cc, map[string]any{"summary": "no findings"}); !cc.Done {
			t.Errorf("a clean account must close on the first finish: %s", out)
		}
	})
}
