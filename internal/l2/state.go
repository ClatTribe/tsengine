package l2

import "github.com/ClatTribe/tsengine/pkg/types"

// State is the run state shared between the agent loop and tool handlers.
// Tools mutate it (advance the phase, emit a finding, set the final
// report); the loop reads it to decide when to stop. It is NOT the
// conversation history (that lives in the loop) — this is the durable
// "crystal memory" the agent commits to, the thing that survives the run.
type State struct {
	// Target is the asset under translation (its L1 findings are the input).
	Target types.Asset

	// Phase is the current workflow phase.
	Phase Phase

	// Findings are the L2-authored vulnerability reports (developer/PM
	// facing: chain narrative + plain-English + remediation). Emitted by
	// create_vulnerability_report in a later wave; empty in L2-0.
	Findings []types.Finding

	// Hypotheses is the Lead's durable plan/scratchpad — the §2.7-LEGIT
	// version of strix's `think` tool. It is a tool (record_hypothesis) NOT
	// because reasoning is a tool (it isn't — §2.7), but because this state
	// must SURVIVE context compaction: a hypothesis written only into the
	// model's response text is dropped when compactHistory replaces the
	// middle. Persisting it here makes it crystal memory — re-surfaced in the
	// compaction summary so a long scan's plan is never lost.
	Hypotheses []Hypothesis

	// Summary is the finish_scan output (executive narrative).
	Summary *FinalReport

	// Done is set by finish_scan — the terminal signal.
	Done bool
}

// Hypothesis is one durable plan item the Lead commits via record_hypothesis.
type Hypothesis struct {
	// Statement is what the Lead believes / wants to test (e.g. "f-001 SQLi
	// and f-004 weak-session may chain to account takeover").
	Statement string `json:"statement"`
	// NextStep is the concrete action the hypothesis implies (e.g. "probe
	// f-001 with dispatch_l2_probe(sqlmap) to confirm dumpability").
	NextStep string `json:"next_step,omitempty"`
}

// FinalReport is the finish_scan artifact: the scan's executive narrative,
// authored entirely as tool PARAMETERS (reasoning-as-parameters, §2.7).
type FinalReport struct {
	ExecutiveSummary string `json:"executive_summary"`
	Methodology      string `json:"methodology,omitempty"`
	Recommendations  string `json:"recommendations,omitempty"`
}

// Outcome is what Agent.Run returns: why it stopped + what it produced +
// what it cost. Recorded for the dashboard + the acceptance gates.
type Outcome struct {
	StopReason  StopReason      `json:"stop_reason"`
	Phase       Phase           `json:"final_phase"`
	Findings    []types.Finding `json:"findings"`
	Summary     *FinalReport    `json:"summary,omitempty"`
	Iterations  int             `json:"iterations"`
	CostUSD     float64         `json:"cost_usd"`
	Tokens      int             `json:"tokens"`
	Compactions int             `json:"compactions"`
	Model       string          `json:"model"`
}
