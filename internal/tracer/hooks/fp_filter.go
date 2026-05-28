// Package hooks implements the L1.5 enrichment hook chain. Each hook
// satisfies tracer.PerFindingHook or tracer.FinalizeHook. The chain
// order is fixed in CLAUDE.md §11; DefaultPerFinding / DefaultFinalize
// (in chain.go) assemble it.
package hooks

import (
	"regexp"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// FPFilter implements hooks 1+2 of CLAUDE.md §11:
//
//	1. pre_emission_fp_filter — drop known-decoy / pure-noise findings
//	2. fp_filter.demote        — lower severity for overrated rules
//
// Both decisions are logged to the audit trail so the security engineer
// can see (and override in webappsec) what L1.5 suppressed. This is the
// "no silent demotions" discipline of CLAUDE.md §1.5.1.
type FPFilter struct {
	drop   []*regexp.Regexp
	demote []demoteRule
}

type demoteRule struct {
	pattern *regexp.Regexp
	to      types.Severity
	reason  string
}

// NewFPFilter builds the default filter. The rule sets are deliberately
// conservative — the L1 audience must never lose a real finding to an
// over-eager filter (CLAUDE.md §2.4: "L1 PRs that improve enrichment but
// regress raw recall are rejected"). These only target findings that are
// pure scanner-noise by construction.
func NewFPFilter() *FPFilter {
	return &FPFilter{
		drop: compileAll([]string{
			// nuclei interactsh self-tests and template-debug artifacts:
			`(?i)^nuclei::self-signed-detect$`,
			`(?i)^nuclei::tech-detect$`,
		}),
		demote: []demoteRule{
			// WAF detection is useful context but not a finding to action
			// on its own — demote to info if a scanner rated it higher.
			{regexp.MustCompile(`(?i)waf-detect`), types.SeverityInfo, "waf detection is informational context"},
		},
	}
}

func (*FPFilter) Name() string { return "fp_filter" }

// Apply drops decoy/noise rules, then demotes overrated rules.
func (h *FPFilter) Apply(f types.Finding) (types.Finding, []types.AuditEntry, bool) {
	for _, re := range h.drop {
		if re.MatchString(f.RuleID) {
			return f, []types.AuditEntry{{
				FindingID: f.ID,
				Action:    "dismiss",
				Rule:      "fp_filter::" + re.String(),
				Reason:    "matched known false-positive / decoy pattern",
			}}, false
		}
	}

	for _, d := range h.demote {
		if d.pattern.MatchString(f.RuleID) && f.Severity.Rank() > d.to.Rank() {
			from := f.Severity
			f.Severity = d.to
			return f, []types.AuditEntry{{
				FindingID:    f.ID,
				Action:       "demote",
				FromSeverity: from,
				ToSeverity:   d.to,
				Rule:         "fp_filter::demote",
				Reason:       d.reason,
			}}, true
		}
	}

	return f, nil, true
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
