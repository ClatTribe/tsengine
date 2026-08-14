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

	// Vendored/third-party dependency de-prioritization: a SAST (code-pattern) finding whose
	// endpoint sits inside a dependency directory (vendor/, node_modules/, site-packages/, …) is
	// real but lives in code the team did NOT write and cannot patch in place — it inflates the
	// first-party actionable count. Demote it to low (NOT dropped) and log it, so findings_raw keeps
	// full severity for the security engineer (§2.4) and webappsec can override. Scoped to code
	// scanners only: a vulnerable vendored DEPENDENCY (trivy/grype/osv) or a leaked secret
	// (gitleaks/trufflehog) is still first-party-actionable, so those tools are never demoted here.
	if sastTools[f.Tool] && f.Severity.Rank() > types.SeverityLow.Rank() && vendoredPathRe.MatchString(f.Endpoint) {
		from := f.Severity
		f.Severity = types.SeverityLow
		return f, []types.AuditEntry{{
			FindingID:    f.ID,
			Action:       "demote",
			FromSeverity: from,
			ToSeverity:   types.SeverityLow,
			Rule:         "fp_filter::vendored-path",
			Reason:       "code finding in a vendored/third-party dependency path — not first-party code the team owns (findings_raw keeps full severity)",
		}}, true
	}

	// Documented PUBLIC SAMPLE credential: a leaked-secret finding whose value is a well-known example
	// from vendor documentation (AWS's own AKIAIOSFODNN7EXAMPLE has appeared in their tutorials for
	// over a decade). It is not a live credential and never was — but left at high/critical it pages a
	// real on-call, which is precisely the alert fatigue an AI-SOC exists to remove. Demote to info +
	// log, so findings_raw keeps it for the security engineer and l15_audit_log makes it recoverable.
	//
	// Matched on the exact known VALUE — never on a rule id, a filename, or a "looks like an example"
	// heuristic. A real key sitting in a file called example.go must keep its severity. Narrowness IS
	// the safety property: this rule suppresses alerts, so a loose match would hide a live leak.
	if sample := documentedPublicSample(f); sample != "" && f.Severity.Rank() > types.SeverityInfo.Rank() {
		from := f.Severity
		f.Severity = types.SeverityInfo
		return f, []types.AuditEntry{{
			FindingID:    f.ID,
			Action:       "demote",
			FromSeverity: from,
			ToSeverity:   types.SeverityInfo,
			Rule:         "fp_filter::documented-sample-credential",
			Reason: "the secret is " + sample + ", a credential published in vendor documentation — not a live " +
				"secret (findings_raw keeps full severity; recoverable via l15_audit_log)",
		}}, true
	}

	// Unpatchable base-image (distro) noise: an OS/distro package CVE that the distro's own security
	// team has marked "wont-fix" — no upstream patch is coming, so the customer cannot remediate it by
	// upgrading, and the distro has already triaged it as not-worth-fixing. This is the classic
	// base-image noise that inflates a container's critical/high count (the case Trivy's
	// --ignore-unfixed targets). Demote to low (NOT dropped) + log, keeping findings_raw at full
	// severity (§2.4). Scoped to a DISTRO "wont-fix" only — a "not-fixed" (fix may still land) or an
	// app-dependency CVE stays actionable — and grounded on the tool's real fix status (never guessed).
	// Covers BOTH container CVE anchors (grype + trivy) via their native OS-package signal.
	if isUnpatchableDistroCVE(f) && f.Severity.Rank() > types.SeverityLow.Rank() {
		from := f.Severity
		f.Severity = types.SeverityLow
		return f, []types.AuditEntry{{
			FindingID:    f.ID,
			Action:       "demote",
			FromSeverity: from,
			ToSeverity:   types.SeverityLow,
			Rule:         "fp_filter::distro-wont-fix",
			Reason:       "OS/distro package CVE the distro marked wont-fix — no upstream patch, unremediable by upgrade (findings_raw keeps full severity)",
		}}, true
	}

	return f, nil, true
}

// isUnpatchableDistroCVE reports whether a container CVE finding is an OS/distro package the distro
// itself won't patch. Both container anchors normalize fix_state to "wont-fix" for that case; the
// OS-package signal is each tool's native field — grype's artifact type (apk/deb/rpm), trivy's result
// class ("os-pkgs"). App-language dependencies (grype npm/pip/…, trivy "lang-pkgs") never match.
func isUnpatchableDistroCVE(f types.Finding) bool {
	if f.ToolArgs["fix_state"] != "wont-fix" {
		return false
	}
	switch f.Tool {
	case "grype":
		return osDistroPkg[f.ToolArgs["pkg_type"]]
	case "trivy":
		return f.ToolArgs["pkg_class"] == "os-pkgs"
	}
	return false
}

// osDistroPkg are grype artifact types that denote a base-OS/distro package (as opposed to an
// app-language dependency). Only these participate in the distro-wont-fix demotion.
var osDistroPkg = map[string]bool{
	"apk": true, // Alpine
	"deb": true, // Debian/Ubuntu
	"rpm": true, // RHEL/CentOS/Fedora/SUSE
}

// sastTools are the code-pattern scanners whose findings point at a source file:line. A finding
// from one of these inside a vendored path is de-prioritized; SCA (trivy/grype/osvscanner) and
// secret (gitleaks/trufflehog) tools are intentionally absent — their vendored-path findings stay
// first-party-actionable.
var sastTools = map[string]bool{
	"semgrep":   true,
	"gosec":     true,
	"bandit":    true,
	"codeql":    true,
	"mobsfscan": true,
}

// vendoredPathRe matches an unambiguous dependency directory anywhere in a file path. Deliberately
// conservative — only directories that hold third-party code by universal convention (no dist/build,
// which can be first-party output).
var vendoredPathRe = regexp.MustCompile(`(?i)(^|/)(vendor|node_modules|third_party|thirdparty|site-packages|\.venv|venv|bower_components|\.yarn)/`)

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// publicSampleCredentials are credential values published in vendor documentation. Each is a literal
// that appears verbatim in official docs/tutorials, so a scanner matching one has matched a document,
// not a secret.
//
// The map is deliberately TINY and exact. This rule lowers severity, so every entry must be a value
// that is provably not live — a broad "example-looking" pattern here would silently bury a real leak,
// which is far worse than the noise it removes. Add an entry only with a citable public source.
var publicSampleCredentials = map[string]string{
	// AWS's canonical example pair, in their docs since ~2010.
	"AKIAIOSFODNN7EXAMPLE":                     "AWS's documented example access-key id (AKIAIOSFODNN7EXAMPLE)",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS's documented example secret access key",
	"ASIAIOSFODNN7EXAMPLE":                     "AWS's documented example session access-key id (ASIAIOSFODNN7EXAMPLE)",
}

// documentedPublicSample returns a human-readable description when the finding's evidence contains a
// known documented sample credential, else "".
//
// It scans the fields a secret scanner puts the matched value into (title, description, endpoint) —
// the same blob the correlator reads — because the concrete value is what makes this safe to act on.
func documentedPublicSample(f types.Finding) string {
	blob := f.Title + " " + f.Description + " " + f.Endpoint
	for value, desc := range publicSampleCredentials {
		if strings.Contains(blob, value) {
			return desc
		}
	}
	return ""
}
