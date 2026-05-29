package l2

import (
	"context"
	"errors"
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// maxToolResultBytes caps a single tool result fed back to the model
// (strix's 2KB inline cap). A chatty tool can't blow the context window;
// the full payload lives in run state / the dashboard, not the transcript.
const maxToolResultBytes = 2048

// Agent is the single L2 Lead. It runs a ReAct loop (generate → act →
// observe) over a phase-gated, ≤12-tool catalog, bounded by a Budget and a
// progress watchdog. One Agent per scan.
type Agent struct {
	client  Client
	catalog Catalog
	budget  Budget
}

// New builds an Agent. It enforces the ≤12 cap up front — a catalog that
// exposes too many tools in any phase is a construction error, never
// shipped to the model (the discipline strix lacked).
func New(client Client, catalog Catalog, budget Budget) (*Agent, error) {
	if client == nil {
		return nil, errors.New("l2: nil client")
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	return &Agent{client: client, catalog: catalog, budget: budget}, nil
}

// Run drives the Lead over the L1 findings for one target and returns the
// Outcome. l1 are the enriched L1 findings (the agent's read-only input);
// st.Findings are the L2-authored reports it emits.
func (a *Agent) Run(ctx context.Context, target types.Asset, l1 []types.Finding) (Outcome, error) {
	system := BuildSystemPrompt(target, l1)
	if len(system) < minSystemPromptBytes {
		// Render guard: never send an empty/tiny prompt (strix's
		// hallucinate-the-whole-scan bug).
		return Outcome{}, fmt.Errorf("l2: system prompt too small (%d < %d bytes) — render bug", len(system), minSystemPromptBytes)
	}

	st := &State{Target: target, Phase: PhaseTriage}
	history := []Message{{Role: RoleUser, Content: "Begin triage of the L1 findings."}}
	a.budget.start()

	compactions := 0
	stop := StopRunning
	for {
		if ctx.Err() != nil {
			stop = StopCancelled
			break
		}
		if r := a.budget.exceeded(); r != StopRunning {
			stop = r
			break
		}
		// Progress watchdog: if stalled and not yet at report, force-advance
		// toward report (strix's no-progress watchdog); if already stalled
		// at report, stop. This guarantees termination on a stuck model.
		if a.budget.stalled() {
			if st.Phase != PhaseReport {
				st.Phase = PhaseReport
				a.budget.markProgress()
				history = append(history, Message{Role: RoleUser,
					Content: "No progress detected — advancing to the report phase. Emit any remaining findings and call finish_scan."})
			} else {
				stop = StopStalled
				break
			}
		}

		tools := a.catalog.exposedIn(st.Phase)
		resp, err := a.client.Generate(ctx, system, history, tools)
		if err != nil {
			return Outcome{}, fmt.Errorf("l2: generate: %w", err)
		}
		a.budget.record(resp.Usage)

		history = append(history, Message{Role: RoleAssistant, Content: resp.Text, ToolCalls: resp.ToolCalls})

		if len(resp.ToolCalls) == 0 {
			// Empty-action guard: nudge the model to act via a tool rather
			// than hang on prose (strix's empty-message guard).
			history = append(history, Message{Role: RoleUser,
				Content: "Take an action via a tool (advance_phase, emit a finding, or finish_scan). Prose alone changes nothing."})
			continue
		}

		phaseBefore, findingsBefore := st.Phase, len(st.Findings)
		for _, call := range resp.ToolCalls {
			res := a.dispatch(ctx, call, st)
			history = append(history, Message{
				Role:       RoleTool,
				ToolCallID: call.ID,
				Content:    truncate(res.Content, maxToolResultBytes),
			})
		}
		// Forward progress = a phase advance or a new finding → reset watchdog.
		if st.Phase != phaseBefore || len(st.Findings) != findingsBefore {
			a.budget.markProgress()
		}

		if st.Done {
			stop = StopFinished
			break
		}

		// Auto-compact when the last turn's REAL context size crossed the
		// window fraction (Claude Code's auto-compact). Deterministic +
		// durable state preserved → "proper analysis" survives a long scan.
		if shouldCompact(resp.Usage.InputTokens, a.client.ContextWindow(), a.budget.CompactAtFraction) {
			before := len(history)
			history = compactHistory(history, a.budget.KeepRecentMsgs, st)
			if len(history) < before {
				compactions++
			}
		}
	}

	return Outcome{
		StopReason:  stop,
		Phase:       st.Phase,
		Findings:    st.Findings,
		Summary:     st.Summary,
		Iterations:  a.budget.iterations,
		CostUSD:     a.budget.spentUSD,
		Tokens:      a.budget.spentToks,
		Compactions: compactions,
		Model:       a.client.Model(),
	}, nil
}

// dispatch executes one tool call against state, applying phase gating with
// an OODA-shaped, ACTIONABLE rejection (strix's 36× finish_scan loop came
// from rejections that explained but didn't tell the model what to do).
func (a *Agent) dispatch(ctx context.Context, call ToolCall, st *State) ToolResult {
	tool, ok := a.catalog.find(call.Name)
	if !ok {
		return ToolResult{Err: true, Content: fmt.Sprintf("unknown tool %q — use only the tools in your catalog", call.Name)}
	}
	if !allowedInPhase(tool.Phases, st.Phase) {
		return ToolResult{Err: true, Content: rejectMsg(call.Name, tool.Phases, st.Phase)}
	}
	res, err := tool.Handler(ctx, call.Args, st)
	if err != nil {
		return ToolResult{Err: true, Content: "tool error: " + err.Error()}
	}
	return res
}

// rejectMsg builds an OODA-shaped, actionable rejection: what happened,
// why it's not allowed now, and the exact next call to make.
func rejectMsg(tool string, want []Phase, current Phase) string {
	target := want[0]
	return fmt.Sprintf(
		"OBSERVE: you called %s in phase %q. ORIENT: %s is only available from phase %q onward. "+
			"DECIDE: advance through the phases first. ACT: call advance_phase (current: %s → %s).",
		tool, current, tool, target, current, nextPhase(current))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}
