package l2

import (
	"fmt"
	"strings"
)

// Context compaction — the mechanism that lets the Lead do PROPER analysis
// on a long scan without hitting the context window (Claude Code's
// auto-compact, adapted).
//
// tsengine's twist over Claude Code: we compact DETERMINISTICALLY (a
// templated summary derived from run State), not with an LLM summary call.
// We can afford to be lossy on the conversational narrative because the
// load-bearing state — findings, plan, surface — lives in durable CRYSTAL
// memory the agent re-reads via tools (get_finding, …), never re-derived
// from prose (the strix "single load-bearing rule"). So compaction:
//   - is free (no extra model call) and reproducible (§10),
//   - keeps the system prompt fixed (cache prefix stable),
//   - keeps the objective (history[0]) + the most recent turns (the "tail"),
//   - replaces the middle with one synthesized progress summary
//     ("lost in the middle" — head+tail are what matter).

// shouldCompact reports whether the last turn's actual context size
// (Response.Usage.InputTokens) crossed the configured fraction of the
// model window. Using the real measured size avoids guessing token counts.
func shouldCompact(lastInputTokens, window int, fraction float64) bool {
	if window <= 0 || lastInputTokens <= 0 || fraction <= 0 {
		return false
	}
	return float64(lastInputTokens) >= fraction*float64(window)
}

// compactHistory replaces the middle of history with a deterministic
// progress summary, preserving the objective (history[0]) and the last
// keepRecent messages. It never orphans a tool_result (the tail is
// extended back so it doesn't start with a RoleTool whose assistant
// tool_use was dropped). Returns history unchanged if there's nothing
// worth compacting.
func compactHistory(history []Message, keepRecent int, st *State) []Message {
	if keepRecent < 1 {
		keepRecent = 1
	}
	// Need: objective(1) + at least one middle msg + tail.
	if len(history) <= keepRecent+2 {
		return history
	}
	cut := len(history) - keepRecent
	// Don't start the tail with an orphaned tool_result.
	for cut < len(history) && history[cut].Role == RoleTool {
		cut++
	}
	if cut <= 1 || cut >= len(history) {
		return history // nothing safe to drop
	}

	out := make([]Message, 0, keepRecent+2)
	out = append(out, history[0]) // objective
	out = append(out, Message{Role: RoleUser, Content: compactionSummary(len(history[1:cut]), st)})
	out = append(out, history[cut:]...)
	return out
}

// compactionSummary is the templated middle-summary. It carries the only
// thing the narrative needs to preserve — progress so far — and points the
// agent back at crystal memory for detail.
func compactionSummary(dropped int, st *State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%d earlier turns compacted to save context. Progress so far: phase=%s, %d finding(s) emitted",
		dropped, st.Phase, len(st.Findings))
	if len(st.Findings) > 0 {
		b.WriteString(": ")
		for i, f := range st.Findings {
			if i >= 10 {
				fmt.Fprintf(&b, ", +%d more", len(st.Findings)-10)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s %s", f.ID, f.Title)
		}
	}
	// Hypotheses are durable crystal memory — the whole reason
	// record_hypothesis is a tool (§2.7) is that the plan must survive THIS
	// compaction. Re-surface it verbatim so a long scan never loses its
	// thread.
	if len(st.Hypotheses) > 0 {
		b.WriteString(". Open hypotheses: ")
		for i, h := range st.Hypotheses {
			if i >= 5 {
				fmt.Fprintf(&b, "; +%d more", len(st.Hypotheses)-5)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(h.Statement)
			if h.NextStep != "" {
				fmt.Fprintf(&b, " (next: %s)", h.NextStep)
			}
		}
	}
	b.WriteString(". Re-read full detail with get_finding; your durable findings/plan are intact.]")
	return b.String()
}
