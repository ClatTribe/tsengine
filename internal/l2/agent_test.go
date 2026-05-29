package l2

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func webTarget() types.Asset {
	return types.Asset{Type: types.AssetWebApplication, Target: "https://x"}
}

// The loop drives through the phases to finish_scan; finish_scan is exposed
// ONLY in the report phase (phase gating).
func TestAgent_DrivesToFinish(t *testing.T) {
	mc := &MockClient{ModelName: "mock", Script: []Response{
		scriptCall("advance_phase", nil, 0.001), // triage→investigate
		scriptCall("advance_phase", nil, 0.001), // investigate→chain
		scriptCall("advance_phase", nil, 0.001), // chain→report
		scriptCall("finish_scan", map[string]any{"executive_summary": "All clear."}, 0.001),
	}}
	a, err := New(mc, CoreTools(), DefaultBudget())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := a.Run(context.Background(), webTarget(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.StopReason != StopFinished {
		t.Errorf("stop = %q, want finished", out.StopReason)
	}
	if out.Phase != PhaseReport || out.Summary == nil || out.Summary.ExecutiveSummary != "All clear." {
		t.Errorf("outcome phase=%q summary=%+v", out.Phase, out.Summary)
	}
	// Phase gating: triage turn (ToolSets[0]) must NOT expose finish_scan.
	if hasTool(mc.ToolSets[0], "finish_scan") {
		t.Error("finish_scan must not be exposed in the triage phase")
	}
	if !hasTool(mc.ToolSets[0], "advance_phase") {
		t.Error("triage should expose advance_phase")
	}
	// The finish turn (last) is in the report phase → finish_scan exposed.
	if !hasTool(mc.ToolSets[len(mc.ToolSets)-1], "finish_scan") {
		t.Error("finish_scan must be exposed in the report phase")
	}
}

// A model that calls advance_phase forever — once at report it's a no-op
// (no progress) — is stopped by the watchdog (StopStalled): guaranteed
// termination on a stuck model.
func TestAgent_WatchdogStopsStuckModel(t *testing.T) {
	script := make([]Response, 0, 20)
	for i := 0; i < 20; i++ {
		script = append(script, scriptCall("advance_phase", nil, 0.0))
	}
	b := DefaultBudget()
	b.MaxIdleTurns = 3
	b.MaxIterations = 50
	a, _ := New(&MockClient{Script: script}, CoreTools(), b)
	out, err := a.Run(context.Background(), webTarget(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.StopReason != StopStalled {
		t.Errorf("stop = %q, want stalled", out.StopReason)
	}
	if out.Phase != PhaseReport {
		t.Errorf("watchdog should have force-advanced to report; phase=%q", out.Phase)
	}
}

// The cost cap halts the run (strix's $2.50/0-findings class of blowup).
func TestAgent_BudgetCostCap(t *testing.T) {
	script := make([]Response, 0, 10)
	for i := 0; i < 10; i++ {
		script = append(script, scriptCall("advance_phase", nil, 0.5))
	}
	b := DefaultBudget()
	b.MaxCostUSD = 1.0
	b.MaxIdleTurns = 0 // disable watchdog to isolate the cost cap
	a, _ := New(&MockClient{Script: script}, CoreTools(), b)
	out, _ := a.Run(context.Background(), webTarget(), nil)
	if out.StopReason != StopBudgetCost {
		t.Errorf("stop = %q, want budget_cost", out.StopReason)
	}
}

// Ctx cancellation stops the loop.
func TestAgent_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a, _ := New(&MockClient{Script: []Response{scriptCall("advance_phase", nil, 0)}}, CoreTools(), DefaultBudget())
	out, _ := a.Run(ctx, webTarget(), nil)
	if out.StopReason != StopCancelled {
		t.Errorf("stop = %q, want cancelled", out.StopReason)
	}
}

// finish_scan in the wrong phase is rejected with an OODA-shaped, actionable
// message (strix's 36× finish_scan loop fix).
func TestDispatch_PhaseRejectionIsActionable(t *testing.T) {
	a, _ := New(&MockClient{}, CoreTools(), DefaultBudget())
	st := &State{Phase: PhaseTriage}
	res := a.dispatch(context.Background(), ToolCall{Name: "finish_scan", Args: map[string]any{}}, st, map[string]int{})
	if !res.Err {
		t.Fatal("finish_scan in triage should be rejected")
	}
	for _, want := range []string{"OBSERVE", "ORIENT", "DECIDE", "ACT", "advance_phase"} {
		if !contains(res.Content, want) {
			t.Errorf("rejection should be OODA-shaped + actionable; missing %q in: %s", want, res.Content)
		}
	}
	if st.Done {
		t.Error("rejected finish_scan must not mark the scan done")
	}
}

// A stubborn model that calls finish_scan in triage over and over, ignoring
// the advance_phase instruction, is auto-bypassed: after autoBypassThreshold
// rejections the loop advances to report on its behalf and runs the call.
// This is the hard backstop for strix's 36× finish_scan rejection loop.
func TestAgent_AutoBypassesRepeatedPhaseRejection(t *testing.T) {
	script := make([]Response, 0, 6)
	for i := 0; i < 6; i++ {
		script = append(script, scriptCall("finish_scan", map[string]any{"executive_summary": "done"}, 0.0))
	}
	b := DefaultBudget()
	b.MaxIdleTurns = 0 // isolate auto-bypass from the watchdog
	a, _ := New(&MockClient{Script: script}, CoreTools(), b)
	out, err := a.Run(context.Background(), webTarget(), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.StopReason != StopFinished {
		t.Errorf("stop = %q, want finished (auto-bypass should let finish_scan run)", out.StopReason)
	}
	if out.Phase != PhaseReport {
		t.Errorf("auto-bypass should advance to report; phase=%q", out.Phase)
	}
	if out.Iterations != autoBypassThreshold {
		t.Errorf("should finish on attempt #%d; iterations=%d", autoBypassThreshold, out.Iterations)
	}
}

func TestNew_EnforcesCapAndNilClient(t *testing.T) {
	if _, err := New(nil, CoreTools(), DefaultBudget()); err == nil {
		t.Error("nil client should error")
	}
	big := CoreTools()
	for i := 0; i < 13; i++ {
		big = append(big, Tool{Schema: ToolSchema{Name: "x", Params: obj(nil)}})
	}
	if _, err := New(&MockClient{}, big, DefaultBudget()); err == nil {
		t.Error("oversize catalog (>12 in a phase) should error")
	}
}

// --- helpers ---
func hasTool(ts []ToolSchema, name string) bool {
	for _, t := range ts {
		if t.Name == name {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
