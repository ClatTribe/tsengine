package remediate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/backport"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// capSubmitter records what the Deliverer queued at the desk.
type capSubmitter struct {
	got []platform.Action
	err error
}

func (c *capSubmitter) Submit(_ context.Context, a platform.Action) (platform.Action, error) {
	if c.err != nil {
		return a, c.err
	}
	c.got = append(c.got, a)
	return a, nil
}

func vulnBefore() []string {
	return strings.Split("func h() {\n\tq := get()\n\trun(\"SELECT \" + q)\n\tdone()\n}", "\n")
}
func vulnAfter() []string {
	return strings.Split("func h() {\n\tq := get()\n\trun(\"SELECT ?\", q)\n\tdone()\n}", "\n")
}

// THE WIRING PlanBackports never had. A delivered code-fix PR now plans backports for the other
// maintained branches and QUEUES them at the same HITL desk — the branch that still has the bug gets
// a proposal, and the branch already carrying the fix gets none (re-applying a security patch is
// itself a failure mode).
func TestDeliverer_PlansAndQueuesBackportsAfterAFixIsDelivered(t *testing.T) {
	hunk, ok := backport.HunkBetween("h.go", vulnBefore(), vulnAfter())
	if !ok {
		t.Fatal("fixture produces no hunk")
	}
	sub := &capSubmitter{}
	d := &Deliverer{
		Submit: sub,
		Backporter: BackportFunc(func(context.Context, platform.Action, platform.Connection, string) (backport.Hunk, []BranchFile, error) {
			return hunk, []BranchFile{
				{Branch: "release/2.3", Path: "h.go", Lines: vulnBefore()}, // still vulnerable → proposal
				{Branch: "release/2.2", Path: "h.go", Lines: vulnAfter()},  // already fixed → nothing
			}, nil
		}),
	}

	fix := platform.Action{
		ID: "act-1", TenantID: "t1", FindingID: "f-1", Kind: platform.ActOpenPR,
		Payload: map[string]any{"full_name": "acme/app"},
	}
	d.planBackports(context.Background(), fix, platform.Connection{Kind: platform.ConnGitHub}, "tok")

	if len(sub.got) != 1 {
		t.Fatalf("want exactly one queued backport (the still-vulnerable branch), got %d: %+v", len(sub.got), sub.got)
	}
	q := sub.got[0]
	if q.Payload["branch"] != "release/2.3" {
		t.Errorf("queued the wrong branch: %v", q.Payload["branch"])
	}
	if q.Payload["remediation_type"] != "backport" {
		t.Errorf("the action is not marked a backport: %v", q.Payload["remediation_type"])
	}
	if q.FindingID != "f-1" {
		t.Errorf("the backport must cite the originating finding, got %q", q.FindingID)
	}
	// It carries the PATCHED content — a PR with no diff is the defect the fix path already closed.
	content, _ := q.Payload["content"].(string)
	if !strings.Contains(content, `"SELECT ?"`) || strings.Contains(content, `" + q`) {
		t.Errorf("the backport PR does not carry the patched file: %q", content)
	}
}

// A backport of a backport is not a thing: the actions this produces are themselves ActOpenPR, so
// without the guard, delivering one would plan backports of it — unbounded.
func TestDeliverer_DoesNotBackportABackport(t *testing.T) {
	sub := &capSubmitter{}
	called := false
	d := &Deliverer{
		Submit: sub,
		Backporter: BackportFunc(func(context.Context, platform.Action, platform.Connection, string) (backport.Hunk, []BranchFile, error) {
			called = true
			return backport.Hunk{}, nil, nil
		}),
	}
	d.planBackports(context.Background(), platform.Action{
		Kind: platform.ActOpenPR, Payload: map[string]any{"remediation_type": "backport"},
	}, platform.Connection{}, "tok")

	if called {
		t.Error("a delivered backport must not itself be backported")
	}
	if len(sub.got) != 0 {
		t.Errorf("nothing should be queued, got %+v", sub.got)
	}
}

// Best-effort by construction: the fix PR is ALREADY OPEN when this runs, so a failure to read the
// branches must never propagate — losing a shipped fix because a branch listing 403'd is strictly
// worse than not backporting. Unwired deployments behave exactly as before.
func TestDeliverer_BackportFailuresNeverDisturbTheDelivery(t *testing.T) {
	fix := platform.Action{Kind: platform.ActOpenPR, TenantID: "t1"}

	// Inputs unavailable → no panic, nothing queued.
	sub := &capSubmitter{}
	d := &Deliverer{Submit: sub, Backporter: BackportFunc(
		func(context.Context, platform.Action, platform.Connection, string) (backport.Hunk, []BranchFile, error) {
			return backport.Hunk{}, nil, errors.New("403 listing branches")
		})}
	d.planBackports(context.Background(), fix, platform.Connection{}, "tok")
	if len(sub.got) != 0 {
		t.Errorf("a failed input read must queue nothing, got %+v", sub.got)
	}

	// A submit failure on one branch must not stop the others.
	hunk, _ := backport.HunkBetween("h.go", vulnBefore(), vulnAfter())
	failing := &capSubmitter{err: errors.New("desk unavailable")}
	d2 := &Deliverer{Submit: failing, Backporter: BackportFunc(
		func(context.Context, platform.Action, platform.Connection, string) (backport.Hunk, []BranchFile, error) {
			return hunk, []BranchFile{{Branch: "release/1.0", Path: "h.go", Lines: vulnBefore()}}, nil
		})}
	d2.planBackports(context.Background(), fix, platform.Connection{}, "tok") // must not panic

	// Not wired at all → today's behaviour.
	(&Deliverer{}).planBackports(context.Background(), fix, platform.Connection{}, "tok")
}

// The branch filter is deliberately conservative: release lines in, dead feature branches out, and
// the base branch out because it already has the fix. Inventing branches spams the customer's repo;
// missing one leaves a bug the next scan still reports — the chosen direction.
func TestMaintainedBranches_KeepsReleaseLinesAndDropsTheRest(t *testing.T) {
	got := MaintainedBranches([]string{
		"main", "release/2.3", "release-1.9", "support/1.x", "v2", "v1.4", "stable",
		"feature/new-ui", "dependabot/npm/lodash", "wip", "hotfix-JIRA-123", "",
	}, "main")

	want := map[string]bool{"release/2.3": true, "release-1.9": true, "support/1.x": true, "v2": true, "v1.4": true, "stable": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly %d release lines", got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("%q is not a maintained release line — backporting to it would spam the repository", g)
		}
	}
	// The base branch already carries the fix.
	for _, g := range got {
		if g == "main" {
			t.Error("the base branch must never be backported to — it is where the fix landed")
		}
	}
}

// THE WIRING TEST WITH TEETH. The tests above call planBackports directly, so they pass even if the
// call site is deleted from Apply — which is precisely the built-but-unwired defect this change
// exists to fix, reproduced inside its own tests. This drives the REAL delivery path end to end:
// Deliverer.Apply -> connector write -> backport planning -> desk. Mutation-verified: removing
// `d.planBackports(...)` from Apply fails this test.
func TestDeliverer_ApplyItselfTriggersBackportPlanning(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t", Kind: platform.ConnGitHub, Status: platform.ConnActive})

	hunk, _ := backport.HunkBetween("h.go", vulnBefore(), vulnAfter())
	sub := &capSubmitter{}
	var applied platform.Action
	d := &Deliverer{
		Store: st, Connectors: connector.NewRegistry(fakeGitHub{applied: &applied}), Tokens: fakeTokens{},
		Submit: sub,
		Backporter: BackportFunc(func(context.Context, platform.Action, platform.Connection, string) (backport.Hunk, []BranchFile, error) {
			return hunk, []BranchFile{{Branch: "release/2.3", Path: "h.go", Lines: vulnBefore()}}, nil
		}),
	}

	act := platform.Action{ID: "a1", TenantID: "t", Kind: platform.ActOpenPR, Payload: map[string]any{"full_name": "acme/web"}}
	if err := d.Apply(ctx, act); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if applied.ID != "a1" {
		t.Fatal("the fix PR itself was not delivered")
	}
	if len(sub.got) != 1 || sub.got[0].Payload["branch"] != "release/2.3" {
		t.Fatalf("Apply did not trigger backport planning — the planner is still unreachable from the "+
			"delivery path, which is the whole defect. queued=%+v", sub.got)
	}
}
