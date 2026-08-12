package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE JOB, not the tools.
//
// Every other test here checks one adapter in isolation, and eight adapters that each work is not the
// same claim as an agent that does the job. What was asked for is "an agent which does the work
// autonomously using the tools at hand, with the human approving changes" — so the thing to verify is
// the CHAIN: one finding, carried by the model from first look to a change waiting at the desk,
// through the real agent loop with the real catalog over a real store.
//
// The model is scripted rather than live because the question here is whether the machinery lets a
// competent agent finish. Whether a given model IS competent is what the per-task benchmarks measure;
// this asks whether the loop would stop it even if it were.

func jobCall(name string, args map[string]any) l2.Response {
	return l2.Response{
		ToolCalls:  []l2.ToolCall{{ID: "c", Name: name, Args: args}},
		StopReason: "tool_use",
		Usage:      l2.Usage{InputTokens: 10, OutputTokens: 10},
	}
}

func TestEngineer_CompletesAWholeJobUnassisted(t *testing.T) {
	d, tid := seedEngineerTenant(t)

	// The exact sequence a competent engineer would run: look at the estate, find where the flaw is,
	// then propose the change. The phase steps are the agent's own — nothing here bypasses gating.
	mc := &l2.MockClient{ModelName: "mock", Script: []l2.Response{
		jobCall("search_estate", map[string]any{"query": "critical injection"}),
		jobCall("advance_phase", nil), // triage → investigate
		jobCall("locate_vulnerability", map[string]any{"finding_id": "f-sqli"}),
		jobCall("advance_phase", nil), // investigate → chain
		jobCall("advance_phase", nil), // chain → report
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli"}),
		jobCall("finish_scan", map[string]any{"executive_summary": "One injection flaw; fix proposed."}),
	}}

	cat := append(l2.CoreTools(), d.EngineerCatalog(tid)...)
	agent, err := l2.New(mc, cat, l2.DefaultBudget())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := agent.Run(context.Background(), engineerTarget(), nil)
	if err != nil {
		t.Fatalf("the agent could not complete a whole job: %v", err)
	}
	if out.StopReason != l2.StopFinished {
		t.Errorf("JOB INCOMPLETE: the agent stopped with %q rather than finishing — a competent model "+
			"was blocked by the machinery, not by its own reasoning", out.StopReason)
	}

	// The point of the whole exercise: a change is waiting for a human, and has NOT been applied.
	sub := d.Submitter.(*recordingSubmitter)
	if len(sub.queued) == 0 {
		t.Fatal("JOB INCOMPLETE: the agent ran to the end and no change reached the desk — the tools " +
			"worked in isolation but the job produced nothing")
	}
	act := sub.queued[len(sub.queued)-1]
	if act.Status == platform.ActApplied {
		t.Errorf("HUMAN BYPASSED: the change was applied rather than queued for approval (status=%q)",
			act.Status)
	}
	if act.FindingID != "f-sqli" {
		t.Errorf("UNGROUNDED: the queued change cites %q, not the finding the job was about", act.FindingID)
	}
}

// Every step must actually have run. A model can call a tool the phase gate rejects and the loop keeps
// going, so "the agent finished" is not by itself evidence the work happened — without this, a job
// where every tool was refused would still pass the test above.
func TestEngineer_EveryStepOfTheJobActuallyRan(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	mc := &l2.MockClient{ModelName: "mock", Script: []l2.Response{
		jobCall("search_estate", map[string]any{"query": "critical injection"}),
		jobCall("advance_phase", nil),
		jobCall("locate_vulnerability", map[string]any{"finding_id": "f-sqli"}),
		jobCall("advance_phase", nil),
		jobCall("advance_phase", nil),
		jobCall("propose_fix", map[string]any{"finding_id": "f-sqli"}),
		jobCall("finish_scan", map[string]any{"executive_summary": "done"}),
	}}
	cat := append(l2.CoreTools(), d.EngineerCatalog(tid)...)
	agent, _ := l2.New(mc, cat, l2.DefaultBudget())
	if _, err := agent.Run(context.Background(), engineerTarget(), nil); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The transcript the model saw back. A phase rejection or a refusal shows up here as the tool's
	// own complaint rather than its result.
	var transcript strings.Builder
	for _, h := range mc.Histories {
		for _, m := range h {
			transcript.WriteString(m.Content + "\n")
		}
	}
	got := transcript.String()
	for _, refusal := range []string{"not allowed in", "cannot be used in", "unknown tool"} {
		if strings.Contains(strings.ToLower(got), refusal) {
			t.Errorf("A STEP WAS REFUSED (%q) — the agent finished, but not by doing the work:\n%s",
				refusal, got)
		}
	}
}

// The tools an engineer needs must be on the list at the point it needs them. A cap enforced by
// splitting tools across phases can strand a job: the model arrives in the phase where it must act and
// the tool it needs is not offered.
//
// Asserted against what the model was ACTUALLY handed each turn, not against the catalog's own
// bookkeeping — the catalog agreeing with itself would prove nothing.
func TestEngineer_NoStepIsStrandedByPhaseGating(t *testing.T) {
	d, tid := seedEngineerTenant(t)
	mc := &l2.MockClient{ModelName: "mock", Script: []l2.Response{
		jobCall("advance_phase", nil), // triage → investigate
		jobCall("advance_phase", nil), // investigate → chain
		jobCall("advance_phase", nil), // chain → report
		jobCall("finish_scan", map[string]any{"executive_summary": "x"}),
	}}
	cat := append(l2.CoreTools(), d.EngineerCatalog(tid)...)
	agent, err := l2.New(mc, cat, l2.DefaultBudget())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := agent.Run(context.Background(), engineerTarget(), nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(mc.ToolSets) < 4 {
		t.Fatalf("expected a turn per phase, got %d", len(mc.ToolSets))
	}
	first, last := mc.ToolSets[0], mc.ToolSets[len(mc.ToolSets)-1]

	// By the final (report) turn — where the job has to end — every acting tool must be on the list,
	// since earlier capabilities stay available later. A missing one means the job cannot finish there.
	for _, want := range []string{"search_estate", "locate_vulnerability", "propose_fix", "open_ticket"} {
		if !offers(last, want) {
			t.Errorf("STRANDED: %q was not offered in the report phase, where the agent must act", want)
		}
	}
	// And the first (triage) turn must NOT offer the acting tools, or the gate means nothing.
	for _, forbidden := range []string{"propose_fix", "open_ticket"} {
		if offers(first, forbidden) {
			t.Errorf("%q is offered during triage — the agent can act before it has looked", forbidden)
		}
	}
	// The cap is per-phase and this is the phase with the most on offer.
	if len(last) > 12 {
		t.Errorf("the report phase offers %d tools, over the 12-tool cap (§2.6)", len(last))
	}
}

func offers(set []l2.ToolSchema, name string) bool {
	for _, s := range set {
		if s.Name == name {
			return true
		}
	}
	return false
}

// engineerTarget is the asset seedEngineerTenant provisions.
func engineerTarget() types.Asset {
	return types.Asset{Type: types.AssetWebApplication, Target: "shop.example.com"}
}
