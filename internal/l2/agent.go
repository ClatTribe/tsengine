package l2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClatTribe/tsengine/internal/llmretry"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// maxToolResultBytes caps a single tool result fed back to the model
// (strix's 2KB inline cap). A chatty tool can't blow the context window;
// the full payload lives in run state / the dashboard, not the transcript.
const maxToolResultBytes = 2048

// autoBypassThreshold is how many times the Lead may call the SAME
// phase-gated tool and be rejected before the loop advances the phase on its
// behalf and runs the call. The hard backstop for strix's 36× finish_scan
// rejection loop: the OODA-shaped rejection TELLS the model to advance_phase;
// if it ignores that this many times, we do it for it rather than spin.
const autoBypassThreshold = 3

// transientRetries is how many extra attempts a TRANSIENT LLM error (rate-limit /
// 5xx / network blip) gets before the agent run aborts. A single transient blip must
// not discard a long pentest/translation's progress — that was the agent's weakest
// reliability link (one Generate error returned from Run, losing every finding so
// far). Permanent errors (bad request / auth) still fail fast.
const transientRetries = 3

// Agent is the single L2 Lead. It runs a ReAct loop (generate → act →
// observe) over a phase-gated, ≤12-tool catalog, bounded by a Budget and a
// progress watchdog. One Agent per scan.
type Agent struct {
	client  Client
	catalog Catalog
	budget  Budget
	// sleep waits d (honoring ctx) between transient-error retries. nil → a real
	// ctx-aware sleep; tests inject a no-op so the retry path doesn't actually wait.
	sleep func(ctx context.Context, d time.Duration) error
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

	// rejected tracks per-tool phase-gate rejections for the auto-bypass
	// backstop. Reset for a tool when it finally runs (consecutive intent).
	rejected := map[string]int{}
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
		resp, err := a.generate(ctx, system, history, tools)
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
			res := a.dispatch(ctx, call, st, rejected)
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

// generate calls the LLM with bounded retry-with-backoff on TRANSIENT errors only
// (rate-limit / 5xx / network). A permanent error (bad request / auth) fails fast — no
// point retrying it. ctx cancellation is honored between attempts. This is the agent's
// reliability backstop: a transient API blip retries instead of discarding the run.
func (a *Agent) generate(ctx context.Context, system string, history []Message, tools []ToolSchema) (Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := a.client.Generate(ctx, system, history, tools)
		if err == nil || !llmretry.IsTransient(err) || attempt >= transientRetries {
			return resp, err // success, a permanent error, or out of retries
		}
		// Exponential backoff: 0.5s, 1s, 2s (capped at 4s), ctx-aware.
		d := time.Duration(500<<attempt) * time.Millisecond
		if d > 4*time.Second {
			d = 4 * time.Second
		}
		if e := a.backoff(ctx, d); e != nil {
			return Response{}, e // ctx cancelled during backoff
		}
	}
}

func (a *Agent) backoff(ctx context.Context, d time.Duration) error {
	if a.sleep != nil {
		return a.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// dispatch executes one tool call against state, applying phase gating with
// an OODA-shaped, ACTIONABLE rejection (strix's 36× finish_scan loop came
// from rejections that explained but didn't tell the model what to do). After
// autoBypassThreshold rejections of the same gated tool, it advances the
// phase on the model's behalf and runs the call — the hard backstop so a
// stubborn model can never spin forever on a gate.
func (a *Agent) dispatch(ctx context.Context, call ToolCall, st *State, rejected map[string]int) ToolResult {
	tool, ok := a.catalog.find(call.Name)
	if !ok {
		return ToolResult{Err: true, Content: fmt.Sprintf("unknown tool %q — use only the tools in your catalog", call.Name)}
	}
	if !allowedInPhase(tool.Phases, st.Phase) {
		rejected[call.Name]++
		if rejected[call.Name] >= autoBypassThreshold {
			rejected[call.Name] = 0
			target := tool.Phases[0]
			for phaseIndex(st.Phase) < phaseIndex(target) {
				st.Phase = nextPhase(st.Phase)
			}
			a.budget.markProgress()
			res := a.runHandler(ctx, tool, call, st)
			res.Content = fmt.Sprintf("[auto-advanced to phase %s after %d rejected attempts] %s",
				st.Phase, autoBypassThreshold, res.Content)
			return res
		}
		return ToolResult{Err: true, Content: rejectMsg(call.Name, tool.Phases, st.Phase)}
	}
	rejected[call.Name] = 0 // the tool ran — reset its streak
	return a.runHandler(ctx, tool, call, st)
}

// runHandler invokes a tool's handler, mapping a Go error to an error result.
func (a *Agent) runHandler(ctx context.Context, tool Tool, call ToolCall, st *State) ToolResult {
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
