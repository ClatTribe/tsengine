package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// THE JOB THAT DIES HALFWAY.
//
// A customer never experiences the happy path failing — they experience the run that stopped partway:
// the model wandered, the budget ran out, someone cancelled. The whole-job test proves a competent
// agent can finish. These ask what the customer is left holding when it does not.
//
// Two things have to be true, and they pull in opposite directions. Work already proposed must SURVIVE
// (a fix the agent produced before dying is real work, and silently binning it means the customer paid
// for a run and got nothing). And the run must not CLAIM to have finished when it did not, or a
// half-done job is filed as a complete one.

// runUntilStop drives the agent with a script and returns the outcome plus the actions left behind.
func runUntilStop(t *testing.T, script []l2.Response, budget l2.Budget) (l2.Outcome, []platform.Action, Deps, string) {
	t.Helper()
	d, tid := seedEngineerTenant(t)
	mc := &l2.MockClient{ModelName: "mock", Script: script}
	cat := l2.BuildCatalog(l2.Deps{Engineer: d.EngineerCatalog(tid)})
	agent, err := l2.New(mc, cat, budget)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := agent.Run(context.Background(), engineerTarget(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out, d.Submitter.(*recordingSubmitter).queued, d, tid
}

// A fix proposed before the run died is real work and must still be at the desk. Discarding it would
// mean a customer pays for a run, the agent does the work, and the result evaporates on a timeout.
func TestAbandoned_WorkProposedBeforeTheEndSurvives(t *testing.T) {
	b := l2.DefaultBudget()
	b.MaxIterations = 6 // dies before it can call finish_scan
	out, queued, _, _ := runUntilStop(t, []l2.Response{
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli"}),
		jobCall("search_estate", map[string]any{"query": "anything else"}),
		jobCall("search_estate", map[string]any{"query": "and again"}),
	}, b)

	if out.StopReason == l2.StopFinished {
		t.Fatalf("the run was supposed to die before finishing, got %q — test no longer exercises the "+
			"abandonment path", out.StopReason)
	}
	if len(queued) == 0 {
		t.Error("WORK LOST: the agent proposed a fix and the run then died, leaving nothing at the desk — " +
			"the customer paid for the run and got nothing")
	}
}

// …and it must still be attributable. An orphaned action nobody can trace to a finding is worse than
// none: a human at the desk is asked to approve a change with no stated cause.
func TestAbandoned_SurvivingWorkIsStillAttributable(t *testing.T) {
	b := l2.DefaultBudget()
	b.MaxIterations = 6
	_, queued, _, _ := runUntilStop(t, []l2.Response{
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli"}),
		jobCall("search_estate", map[string]any{"query": "x"}),
		jobCall("search_estate", map[string]any{"query": "y"}),
	}, b)
	for _, a := range queued {
		if a.FindingID == "" {
			t.Errorf("ORPHANED: action %s survived an abandoned run with no finding attached — a human "+
				"is asked to approve a change with no stated cause", a.ID)
		}
		if a.Status == platform.ActApplied {
			t.Errorf("action %s was APPLIED by a run that did not finish", a.ID)
		}
	}
}

// The run must not report finished when it was not. A half-done job filed as complete is how a
// customer concludes an asset was handled when it was abandoned mid-way.
func TestAbandoned_DoesNotClaimToHaveFinished(t *testing.T) {
	b := l2.DefaultBudget()
	b.MaxIterations = 3
	out, _, _, _ := runUntilStop(t, []l2.Response{
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
	}, b)
	if out.StopReason == l2.StopFinished {
		t.Error("DISHONEST OUTCOME: a run that never called finish_scan reported itself finished")
	}
	if out.StopReason == l2.StopRunning {
		t.Error("a terminated run reported no stop reason at all — the caller cannot tell what happened")
	}
}

// Cancellation is the operator pulling the plug, and it must not leave the customer's findings altered
// by a run that was stopped. Nothing half-written.
func TestAbandoned_CancellationLeavesFindingsUntouched(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	before := findingByID(t, d, tid, "f-sqli")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pulled before the first turn

	mc := &l2.MockClient{ModelName: "mock", Script: []l2.Response{
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli"}),
	}}
	cat := l2.BuildCatalog(l2.Deps{Engineer: d.EngineerCatalog(tid)})
	agent, _ := l2.New(mc, cat, l2.DefaultBudget())
	out, err := agent.Run(ctx, engineerTarget(), nil)
	if err == nil && out.StopReason != l2.StopCancelled {
		t.Errorf("a cancelled run reported %q rather than cancelled", out.StopReason)
	}

	after := findingByID(t, d, tid, "f-sqli")
	if after.VerificationStatus != before.VerificationStatus || after.Severity != before.Severity {
		t.Errorf("MUTATED BY A DEAD RUN: finding changed from %s/%s to %s/%s",
			before.Severity, before.VerificationStatus, after.Severity, after.VerificationStatus)
	}
	if len(d.Submitter.(*recordingSubmitter).queued) != 0 {
		t.Error("a run cancelled before its first turn still queued an action")
	}
}
