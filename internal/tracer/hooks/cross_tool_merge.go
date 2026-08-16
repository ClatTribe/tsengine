package hooks

import (
	"net/url"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// CrossToolMerge implements hook 9 of CLAUDE.md §11. It collapses exact
// duplicate findings — same (tool, rule_id, endpoint) — into a single
// entry, recording each merge in the audit log.
//
// Conservative by design: it merges only duplicates of the SAME (tool, rule_id, endpoint-modulo-
// payload), which arise from replay-append, re-scan, or an injection tool reporting one finding per
// working payload. It never merges near-duplicates ACROSS tools.
// Cross-tool agreement is the corroborator's job (which runs first and
// has already annotated corroborated_by); collapsing those would lose
// the multi-source signal the security engineer wants to see.
type CrossToolMerge struct{}

// NewCrossToolMerge constructs the hook.
func NewCrossToolMerge() *CrossToolMerge { return &CrossToolMerge{} }

func (*CrossToolMerge) Name() string { return "cross_tool_merge" }

// dedupEndpoint normalizes an endpoint for duplicate detection by dropping query-parameter VALUES
// while keeping their names.
//
// Injection tools report one finding per payload that worked, and the payload lives in the URL:
//
//	…/Case02-Tag2TagScope.jsp?userinput=textvalue%27%3E%3Cscript%3Ealert%281%29…
//
// Every variant is therefore a different endpoint, so an exact-match key never collides and nothing
// merges. Measured on WAVSEP's 32-case reflected-XSS set: dalfox produced 751 findings over 9
// genuinely vulnerable cases — 426 for one case alone — and findings_enriched was also 751 with ZERO
// audit entries. A customer scanning their own app sees 751 XSS findings for 9 vulnerabilities.
//
// Parameter NAMES are kept because ?a= and ?b= being injectable are two different vulnerabilities;
// only the values are dropped, because "which payload proved it" is evidence, not identity. The same
// normalization takes that run to 13 findings.
func dedupEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.RawQuery == "" {
		return endpoint
	}
	names := make([]string, 0, 4)
	for name := range u.Query() {
		names = append(names, name)
	}
	sort.Strings(names) // parameter order is not part of the vulnerability
	u.RawQuery = ""
	return u.String() + "?" + strings.Join(names, "&")
}

// Finalize removes exact duplicates, keeping the first occurrence.
func (h *CrossToolMerge) Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry) {
	seen := map[string]int{} // dedup key -> index in out
	out := make([]types.Finding, 0, len(findings))
	var audit []types.AuditEntry

	for _, f := range findings {
		k := f.Tool + "|" + f.RuleID + "|" + dedupEndpoint(f.Endpoint)
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
