package cloudagent

import "github.com/ClatTribe/tsengine/internal/cloudgraph"

// toolselect.go applies minimal-tool-list discipline to the cloud engineer (the harness-engineering
// principle: show the LLM only the tools usable RIGHT NOW). Unlike the offensive agent (24 tools, clear
// recon→exploit→report phases), the cloud engineer's catalog is a COHESIVE 12-tool reasoner already at the
// §2.6 cap — its analysis tools (resolve_access / find_paths / blast_radius / detect_privesc) apply
// throughout an investigation, so over-phasing them would hurt. Only two tools have a real precondition,
// and gating them is correct, not arbitrary:
//
//   - propose_fix     — you cannot propose a fix before an issue is recorded (nothing to fix);
//   - rightsize_principal (CIEM) — no-ops without observed usage data, so showing it then is pure noise.
//
// The dispatch registry (agent.go) keeps every tool, so a gated tool called anyway still works —
// disclosure is an accuracy optimization, never a capability gate.

func selectTools(cc *Context) []toolDef {
	showFix := cc != nil && len(cc.Issues) > 0
	showRightsize := cc != nil && snapshotHasUsageData(cc.Snap)
	out := make([]toolDef, 0, len(tools()))
	for _, t := range tools() {
		switch t.name {
		case "propose_fix":
			if !showFix {
				continue
			}
		case "rightsize_principal":
			if !showRightsize {
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

// snapshotHasUsageData reports whether any principal in the snapshot carries observed usage data — the
// precondition for CIEM rightsizing to produce anything.
func snapshotHasUsageData(snap *cloudgraph.Snapshot) bool {
	if snap == nil {
		return false
	}
	for _, n := range snap.Nodes {
		if n != nil && n.Kind == cloudgraph.KindPrincipal && n.Attrs != nil && n.Attrs["usage_observed"] == "true" {
			return true
		}
	}
	return false
}
