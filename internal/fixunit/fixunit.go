// Package fixunit answers one question, in one place: WHICH FINDINGS ARE FIXED BY THE SAME CHANGE?
//
// It exists because two features need that answer and must not disagree about it. The remediation
// engine groups findings into one bulk PR per fix unit (internal/remediate); the VAPT report's
// remediation roadmap tells the customer "step 1 closes these 4 findings". If those two derived the
// grouping separately, the plan a customer executes and the pull requests the product actually
// opens would describe different work — the roadmap promising one step where the engine files three.
//
// It cannot live in either caller: internal/remediate depends (via internal/runner) on internal/grc,
// so grc importing remediate is an import cycle. A leaf package both can import is the fix, and the
// shared definition is the point rather than a side effect.
//
// Grounded (§10): the key is derived from real tool output — a package coordinate the scanner
// reported, else the rule id — never guessed and never inferred from prose.
package fixunit

import "github.com/ClatTribe/tsengine/pkg/types"

// Key returns the remediation unit a finding belongs to. Findings sharing a key are fixable by one
// change:
//   - SCA findings → the package coordinate (pkg@installed_version): every CVE in lodash@4.17.0 is
//     fixed by one upgrade.
//   - everything else → the rule id: the same rule across files is one fix pattern.
func Key(f types.Finding) string {
	if pkg := f.ToolArgs["pkg"]; pkg != "" {
		return "pkg:" + pkg + "@" + f.ToolArgs["installed_version"]
	}
	return "rule:" + f.RuleID
}

// Group is a set of findings fixable by one remediation, in stable order.
type Group struct {
	Key      string
	Findings []types.Finding
}

// Group buckets findings by fix unit, preserving first-seen order (of the groups, and of findings
// within a group) so callers are deterministic.
func GroupBy(findings []types.Finding) []Group {
	idx := map[string]int{}
	var groups []Group
	for _, f := range findings {
		k := Key(f)
		i, ok := idx[k]
		if !ok {
			idx[k] = len(groups)
			groups = append(groups, Group{Key: k})
			i = idx[k]
		}
		groups[i].Findings = append(groups[i].Findings, f)
	}
	return groups
}
