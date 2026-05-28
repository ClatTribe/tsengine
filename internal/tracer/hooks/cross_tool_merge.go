package hooks

import "github.com/ClatTribe/tsengine/pkg/types"

// CrossToolMerge implements hook 9 of CLAUDE.md §11. It collapses exact
// duplicate findings — same (tool, rule_id, endpoint) — into a single
// entry, recording each merge in the audit log.
//
// Conservative by design: it only merges EXACT duplicates (which arise
// from replay-append or re-scan), never near-duplicates across tools.
// Cross-tool agreement is the corroborator's job (which runs first and
// has already annotated corroborated_by); collapsing those would lose
// the multi-source signal the security engineer wants to see.
type CrossToolMerge struct{}

// NewCrossToolMerge constructs the hook.
func NewCrossToolMerge() *CrossToolMerge { return &CrossToolMerge{} }

func (*CrossToolMerge) Name() string { return "cross_tool_merge" }

// Finalize removes exact duplicates, keeping the first occurrence.
func (h *CrossToolMerge) Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry) {
	seen := map[string]int{} // dedup key -> index in out
	out := make([]types.Finding, 0, len(findings))
	var audit []types.AuditEntry

	for _, f := range findings {
		k := f.Tool + "|" + f.RuleID + "|" + f.Endpoint
		if _, dup := seen[k]; dup {
			audit = append(audit, types.AuditEntry{
				FindingID: f.ID,
				Action:    "merge",
				Rule:      "cross_tool_merge::exact-duplicate",
				Reason:    "collapsed into earlier identical finding (" + f.Tool + " " + f.RuleID + " @ " + f.Endpoint + ")",
			})
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out, audit
}
