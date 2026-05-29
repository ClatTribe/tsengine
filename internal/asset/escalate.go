package asset

import (
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// EscalationPlanner is the OPTIONAL deterministic "conditional depth"
// capability. After the detection stage, the orchestrator hands a handler
// its own findings + surface and asks: given what we found, which DEEP
// tools are now worth running, and where?
//
// This is the L1 (reproducible, no-LLM) half of "which tool when". It
// covers the KNOWN signal→tool mappings — e.g. a /graphql endpoint → inql,
// a discovered login → hydra, a semgrep injection finding → CodeQL on that
// language. The open-ended "what's interesting here" reasoning is L2's job
// (dispatch_l2_probe, Phase 6). Keeping the known mappings here means they
// fire every run, cheaply, and reproducibly (CLAUDE.md §10) — and that
// expensive tools fire ONLY where a signal points, never blanket.
type EscalationPlanner interface {
	PlanEscalation(target types.Asset, surface []string, findings []types.Finding) []Dispatch
}

// Trigger is one rule in a per-asset escalation table: "when this signal
// appears, run this depth tool with these args". A handler builds its
// table and evaluates it with EvalTriggers inside PlanEscalation.
//
// Exactly one of MatchFinding / MatchSurface is used per trigger. Each
// returns the dispatch args (so a finding's endpoint/CWE can shape the
// args) or ok=false to skip.
type Trigger struct {
	// Name labels the trigger for provenance/logging (e.g. "graphql→inql").
	Name string
	// Tool is the depth tool to dispatch. Resolved against the registry;
	// an unregistered tool is skipped (graceful in dev images).
	Tool string
	// MatchFinding fires off a detection finding (rule_id/CWE/endpoint).
	MatchFinding func(types.Finding) (tool.Args, bool)
	// MatchSurface fires off a recon surface entry (URL/host:port/op).
	MatchSurface func(entry string) (tool.Args, bool)
}

// EvalTriggers runs a trigger table over the detection findings + surface
// and returns the depth dispatches, deduped by (tool, target) so the same
// probe isn't queued twice from many matching signals. resolve maps a tool
// name to its registered Tool (nil → skip). Order is deterministic:
// findings first (in order), then surface (in order), per trigger order.
func EvalTriggers(triggers []Trigger, surface []string, findings []types.Finding, resolve func(string) (tool.Tool, bool)) []Dispatch {
	seen := map[string]struct{}{}
	var out []Dispatch

	emit := func(tr Trigger, args tool.Args) {
		t, ok := resolve(tr.Tool)
		if !ok {
			return
		}
		key := tr.Tool + "\x00" + dispatchTarget(args)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Dispatch{Tool: t, Args: args, EscalatedFrom: tr.Name})
	}

	for _, tr := range triggers {
		if tr.MatchFinding != nil {
			for _, f := range findings {
				if args, ok := tr.MatchFinding(f); ok {
					emit(tr, args)
				}
			}
		}
		if tr.MatchSurface != nil {
			for _, e := range surface {
				if args, ok := tr.MatchSurface(e); ok {
					emit(tr, args)
				}
			}
		}
	}
	return out
}

// dispatchTarget returns the dedup key for a dispatch's primary target.
func dispatchTarget(args tool.Args) string {
	for _, k := range []string{"target", "targets", "spec_url", "login_url"} {
		if v, ok := args[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
