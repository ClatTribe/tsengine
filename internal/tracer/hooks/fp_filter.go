// Package hooks implements the L1.5 enrichment hook chain. Each hook
// satisfies tracer.PerFindingHook or tracer.FinalizeHook. The chain
// order is fixed in CLAUDE.md §11; DefaultPerFinding / DefaultFinalize
// (in chain.go) assemble it.
package hooks

import (
	"regexp"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// FPFilter implements hooks 1+2 of CLAUDE.md §11:
//
//  1. pre_emission_fp_filter — drop known-decoy / pure-noise findings
//  2. fp_filter.demote        — lower severity for overrated rules
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
	// requireNoCWE makes the rule fire ONLY when the finding carries no CWE.
	// This is the structural recall guard for the broad fingerprint patterns
	// (`-detect`, favicon): a real vulnerability is CWE-classified, so a
	// CWE-bearing finding is never demoted by a fingerprint rule even if its
	// rule_id happens to match.
	requireNoCWE bool
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
			{regexp.MustCompile(`(?i)waf-detect`), types.SeverityInfo, "waf detection is informational context", false},
			// Technology / service FINGERPRINTS (nuclei's `-detect` convention:
			// nginx-detect, wordpress-detect, jira-detect, …) are inventory /
			// recon, not vulnerabilities — yet a scanner may rate them low/medium,
			// inflating the actionable finding count (a false positive in the
			// "is this a real issue?" sense). Demote to info. Guarded by
			// requireNoCWE so a CWE-classified vulnerability is never touched
			// (the recall-safety invariant — pre-L1.5 findings_raw keeps full
			// severity regardless; this only shapes the enriched/L2/VAPT view).
			{regexp.MustCompile(`(?i)-detect$`), types.SeverityInfo, "technology/service fingerprint (nuclei -detect) — inventory, not a vulnerability", true},
			{regexp.MustCompile(`(?i)favicon`), types.SeverityInfo, "favicon-hash fingerprint — inventory, not a vulnerability", true},
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
		if d.requireNoCWE && len(f.CWE) > 0 {
			continue // CWE-classified → a real vulnerability, never a fingerprint
		}
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

	// A leaked-secret finding whose value is a DOCUMENTED PUBLIC SAMPLE credential (e.g. AWS's
	// own example key AKIAIOSFODNN7EXAMPLE, in every tutorial for ~15 years) is a textbook false
	// positive — it is not a live credential. Left at high/critical it pages a real SOC (the
	// alert-fatigue the AI-SOC category exists to kill; surfaced by `tsbench triage`). Demote to
	// info + audit so it never opens an incident, while findings_raw keeps it for the security
	// engineer (§2.5, recoverable via l15_audit_log). Content-matched (not rule-id) and narrow to
	// the exact known sample values, so a real key is never touched.
	if sample := documentedPublicSample(f); sample != "" && f.Severity.Rank() > types.SeverityInfo.Rank() {
		from := f.Severity
		f.Severity = types.SeverityInfo
		return f, []types.AuditEntry{{
			FindingID:    f.ID,
			Action:       "demote",
			FromSeverity: from,
			ToSeverity:   types.SeverityInfo,
			Rule:         "fp_filter::public-sample-credential",
			Reason:       "leaked value is a documented public sample credential (" + sample + "), not a live secret",
		}}, true
	}

	return f, nil, true
}

// documentedPublicSampleValues are credentials that appear verbatim in official public
// documentation/tutorials and are therefore NOT live secrets. A finding whose leaked value is
// one of these is a known false positive. Kept narrow + exact — never a substring/heuristic.
var documentedPublicSampleValues = []string{
	"AKIA" + "IOSFODNN7EXAMPLE",                     // AWS's canonical example access key id
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY", // AWS's canonical example secret access key
}

// documentedPublicSample returns the matched sample value if the finding's leaked content is a
// documented public sample credential, else "". Scoped to secret/credential-class findings.
func documentedPublicSample(f types.Finding) string {
	rid := strings.ToLower(f.RuleID)
	if !strings.Contains(rid, "gitleaks") && !strings.Contains(rid, "trufflehog") &&
		!strings.Contains(rid, "secret") && !strings.Contains(rid, "key") && !strings.Contains(rid, "credential") {
		return ""
	}
	blob := f.Title + " " + f.Description
	for _, s := range documentedPublicSampleValues {
		if strings.Contains(blob, s) {
			return s
		}
	}
	return ""
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
