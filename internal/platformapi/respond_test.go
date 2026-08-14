package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func triageCount(t *testing.T, d Deps, tid string) int {
	t.Helper()
	all, err := d.Store.ListAIAnalyses(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range all {
		if a.Kind == "triage" {
			n++
		}
	}
	return n
}

// THE RESPONSE HALF, end to end: an event-driven incident opening drives an actual AI-engineer review
// (a persisted triage), for an AI-entitled tenant.
func TestRespond_RunsTheEngineerForAnEntitledTenant(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("advance_phase", nil), jobCall("advance_phase", nil), jobCall("advance_phase", nil),
		jobCall("finish_scan", map[string]any{"executive_summary": "reviewed the takeover"}),
	})
	// The seam the detached goroutine calls; driven synchronously so the effect is observable.
	d.runIncidentResponse(context.Background(), tid, 1)
	if got := triageCount(t, d, tid); got == 0 {
		t.Error("an entitled tenant's event-driven incident did not produce an engineer review")
	}
}

// THE ECONOMIC GATE holds on this path too: a Free tenant with no key of its own triggers NO operator
// LLM spend when an incident opens. Without this, the response path would be a hole in the invariant
// the scan path already guards.
func TestRespond_FreeTenantWithoutKeySpendsNothing(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{
		jobCall("advance_phase", nil), jobCall("advance_phase", nil), jobCall("advance_phase", nil),
		jobCall("finish_scan", map[string]any{"executive_summary": "should never run"}),
	})
	tn, _ := d.Store.GetTenant(context.Background(), tid)
	tn.Plan = platform.PlanFree
	if err := d.Store.PutTenant(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	d.runIncidentResponse(context.Background(), tid, 1)
	if got := triageCount(t, d, tid); got != 0 {
		t.Errorf("ECONOMIC GATE OPEN: a Free tenant's incident drove the operator LLM (%d triages)", got)
	}
}

// The public entry point detaches and returns promptly. We can at least assert it does not panic and is
// a no-op for an empty batch (the guard before the goroutine).
func TestRespond_EmptyBatchIsANoOp(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	d.RespondToIncidents(context.Background(), tid, nil)
	if got := triageCount(t, d, tid); got != 0 {
		t.Errorf("an empty batch produced %d triages, want 0", got)
	}
}
