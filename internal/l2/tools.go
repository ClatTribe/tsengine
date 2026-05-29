package l2

import (
	"context"
	"fmt"
)

// MaxCatalog is the hard ≤12-tool cap (Invariant L2-CAP, CLAUDE.md §2.6):
// past ~12 tools the LLM's tool-use accuracy degrades steeply. strix never
// enforced its own budget and its catalog drifted 60→90; this is a hard
// ceiling, gated by Catalog.Validate + a CI test in a later wave.
const MaxCatalog = 12

// ToolResult is a tool handler's output, fed back to the model as a
// tool-result turn. Content is kept small (the loop caps it) so a chatty
// tool can't blow the context window.
type ToolResult struct {
	Content string
	Err     bool
}

// Tool is one entry in the L2 catalog: the schema the LLM sees, the phases
// it's allowed in, and the handler that executes it against run State.
// Handlers are the ONLY place a tool's side-effect happens — reasoning
// never is a tool (§2.7).
type Tool struct {
	Schema  ToolSchema
	Phases  []Phase // allowed phases; empty = all
	Handler func(ctx context.Context, args map[string]any, st *State) (ToolResult, error)
}

// Catalog is the per-asset tool set exposed to the Lead.
type Catalog []Tool

// exposedIn returns the schemas available in a given phase (phase-filtered).
// This is "what the LLM sees" that the ≤12 cap counts.
func (c Catalog) exposedIn(p Phase) []ToolSchema {
	var out []ToolSchema
	for _, t := range c {
		if allowedInPhase(t.Phases, p) {
			out = append(out, t.Schema)
		}
	}
	return out
}

// find returns the tool by name (used by the loop to dispatch a call).
func (c Catalog) find(name string) (Tool, bool) {
	for _, t := range c {
		if t.Schema.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Validate enforces the ≤12 cap PER PHASE — the count the LLM actually
// sees in any single turn must never exceed MaxCatalog.
func (c Catalog) Validate() error {
	for _, p := range phaseOrder {
		if n := len(c.exposedIn(p)); n > MaxCatalog {
			return fmt.Errorf("l2: catalog exposes %d tools in phase %q, exceeds the ≤%d cap (L2-CAP)", n, p, MaxCatalog)
		}
	}
	return nil
}

// CoreTools are the framework tools every asset catalog includes: orient
// (think), workflow control (advance_phase), and the terminal commit
// (finish_scan). Per-asset waves add the read-state / probe / report tools
// on top, staying within the cap.
func CoreTools() Catalog {
	return Catalog{
		{
			Schema: ToolSchema{
				Name:        "think",
				Description: "Record reasoning/plan to your scratchpad. No side effect; use it to orient before acting. Does NOT emit a finding.",
				Params: obj(map[string]any{
					"thought": str("your reasoning"),
				}, "thought"),
			},
			Handler: func(_ context.Context, args map[string]any, _ *State) (ToolResult, error) {
				return ToolResult{Content: "noted"}, nil
			},
		},
		{
			Schema: ToolSchema{
				Name:        "advance_phase",
				Description: "Advance the workflow to the next phase (triage→investigate→chain→report) when the current phase's work is done. finish_scan is only available in the report phase.",
				Params:      obj(map[string]any{}, ),
			},
			Handler: func(_ context.Context, _ map[string]any, st *State) (ToolResult, error) {
				prev := st.Phase
				st.Phase = nextPhase(st.Phase)
				if st.Phase == prev {
					return ToolResult{Content: "already at the final phase (report)"}, nil
				}
				return ToolResult{Content: fmt.Sprintf("advanced to phase: %s", st.Phase)}, nil
			},
		},
		{
			Schema: ToolSchema{
				Name:        "finish_scan",
				Description: "Terminate the scan and emit the executive report. Only valid in the report phase. All narrative rides as parameters here.",
				Params: obj(map[string]any{
					"executive_summary": str("1-2 paragraph executive summary for a non-security audience"),
					"methodology":       str("how the scan was conducted"),
					"recommendations":   str("prioritized next steps"),
				}, "executive_summary"),
			},
			Phases: []Phase{PhaseReport},
			Handler: func(_ context.Context, args map[string]any, st *State) (ToolResult, error) {
				st.Summary = &FinalReport{
					ExecutiveSummary: argStr(args, "executive_summary"),
					Methodology:      argStr(args, "methodology"),
					Recommendations:  argStr(args, "recommendations"),
				}
				st.Done = true
				return ToolResult{Content: "scan finished"}, nil
			},
		},
	}
}

// --- tiny JSON-schema helpers ---------------------------------------

func obj(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func argStr(args map[string]any, k string) string {
	if v, ok := args[k].(string); ok {
		return v
	}
	return ""
}
