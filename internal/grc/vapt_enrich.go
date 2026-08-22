package grc

import (
	"fmt"
	"strings"
)

// VAPT report enrichment — the layer that brings the report to pentest-deliverable parity:
// per-finding remediation guidance + OWASP Top 10 (2021) mapping + a prose executive summary.
// All grounded: remediation is the standard fix for the finding's CWE class (not invented per
// finding), and OWASP/CWE mappings are the published crosswalks — nothing asserted beyond what
// the finding's identifiers support.

// cweRemediation maps a CWE to the standard, actionable fix a pentester would write. Keyed by
// the bare "CWE-NNN".
var cweRemediation = map[string]string{
	"CWE-89":  "Use parameterized queries / prepared statements; never concatenate user input into SQL. Run the app under a least-privilege database account.",
	"CWE-79":  "Context-encode all output (HTML/JS/URL/attribute); rely on the framework's auto-escaping; deploy a strict Content-Security-Policy.",
	"CWE-78":  "Avoid invoking a shell; use a safe library/exec API with an argument array. If a shell is unavoidable, allowlist arguments and never pass raw user input.",
	"CWE-94":  "Never eval or deserialize untrusted input; use safe parsers, disable dynamic code paths, and sandbox any required dynamic execution.",
	"CWE-22":  "Canonicalize and validate file paths against an allowlisted base directory; reject `..` and absolute paths; prefer opaque IDs over filenames.",
	"CWE-918": "Allowlist outbound destinations; block link-local/cloud-metadata IP ranges (169.254.0.0/16); resolve and validate the target before making the request.",
	"CWE-352": "Add anti-CSRF tokens (synchronizer or double-submit) to state-changing requests and set cookies SameSite=Lax/Strict.",
	"CWE-200": "Remove sensitive data from responses and error messages; enforce object-level authorization on every access; disable verbose stack traces in production.",
	"CWE-798": "Remove the hard-coded secret from source, rotate the exposed credential immediately, and load secrets from a managed secret store at runtime.",
	"CWE-347": "Pin the expected signing algorithm and reject `alg:none`; verify the signature against trusted keys; validate `exp`/`aud`/`iss`.",
	"CWE-327": "Replace the weak algorithm with a modern primitive (AES-GCM, SHA-256+); remove MD5/SHA-1/DES/RC4.",
	"CWE-326": "Increase key strength to current standards (RSA ≥ 3072 / AES ≥ 256) and enforce TLS 1.2+ with strong ciphers.",
	"CWE-125": "Bounds-check all buffer reads; upgrade the affected dependency to a patched version; enable memory-safety mitigations (ASAN/fortify) in CI.",
	"CWE-787": "Bounds-check all buffer writes; upgrade the affected dependency to a patched version; enable stack canaries/ASLR.",
	"CWE-506": "Remove or replace the compromised dependency immediately, rotate any secrets it could have accessed, and audit build provenance / pin checksums.",
	"CWE-693": "Restore the missing security control (e.g. the absent header or flag) and verify it is enforced on every code path, not just the happy path.",
	// The classes the AI pentester actively discovers/proves — give each a proper fix so a proven
	// finding never falls through to the generic default in the VAPT deliverable.
	"CWE-943":  "Never build NoSQL queries from raw request data; cast/validate types (reject object-valued params where a scalar is expected) and use the driver's parameterized query API so `$`-operators can't be injected.",
	"CWE-1336": "Don't render user input through the template engine; use logic-less templates or a sandboxed engine, pass user data as bound variables (never concatenated into the template), and disable dynamic template loading.",
	"CWE-98":   "Never pass user input to include/require; use an allowlist of includable files, disable remote URL includes (allow_url_include=off), and prefer opaque IDs over paths.",
	"CWE-601":  "Validate redirect targets against an allowlist of same-site paths/hosts; never redirect to a raw user-supplied URL; prefer relative paths or mapped keys.",
	"CWE-639":  "Enforce object-level authorization on every request — check the authenticated principal owns/may access the referenced object server-side (don't trust a client-supplied ID); prefer unguessable IDs as defense-in-depth.",
	"CWE-269":  "Enforce role/privilege checks server-side on every state-changing action; never let a user set their own role/privilege fields; re-derive authorization from the session, not request data.",
	"CWE-915":  "Bind only an explicit allowlist of fields from the request (no mass/auto-binding to internal attributes like role/is_admin/balance); separate the input DTO from the persistence model.",
	"CWE-287":  "Fix the authentication bypass: enforce the check server-side on every path, remove default/guessable credentials, and require re-authentication for sensitive actions.",
	"CWE-611":  "Disable external entity resolution in the XML parser (disallow DOCTYPE/DTDs, set FEATURE_SECURE_PROCESSING); prefer a hardened parser configuration or a non-XML format.",
}

// cweOWASP maps a CWE to its OWASP Top 10 (2021) category.
var cweOWASP = map[string]string{
	"CWE-22":   "A01:2021 Broken Access Control",
	"CWE-200":  "A01:2021 Broken Access Control",
	"CWE-352":  "A01:2021 Broken Access Control",
	"CWE-327":  "A02:2021 Cryptographic Failures",
	"CWE-326":  "A02:2021 Cryptographic Failures",
	"CWE-89":   "A03:2021 Injection",
	"CWE-79":   "A03:2021 Injection",
	"CWE-78":   "A03:2021 Injection",
	"CWE-94":   "A03:2021 Injection",
	"CWE-943":  "A03:2021 Injection",
	"CWE-1336": "A03:2021 Injection",
	"CWE-98":   "A03:2021 Injection",
	"CWE-639":  "A01:2021 Broken Access Control",
	"CWE-269":  "A01:2021 Broken Access Control",
	"CWE-601":  "A01:2021 Broken Access Control",
	"CWE-915":  "A08:2021 Software and Data Integrity Failures",
	"CWE-287":  "A07:2021 Identification and Authentication Failures",
	"CWE-611":  "A05:2021 Security Misconfiguration",
	"CWE-693":  "A05:2021 Security Misconfiguration",
	"CWE-125":  "A06:2021 Vulnerable and Outdated Components",
	"CWE-787":  "A06:2021 Vulnerable and Outdated Components",
	"CWE-798":  "A07:2021 Identification and Authentication Failures",
	"CWE-347":  "A07:2021 Identification and Authentication Failures",
	"CWE-506":  "A08:2021 Software and Data Integrity Failures",
	"CWE-918":  "A10:2021 Server-Side Request Forgery (SSRF)",
}

// remediationFor returns the standard fix for the finding's CWE(s), or a tool-class default.
func remediationFor(cwes []string, tool string) string {
	for _, c := range cwes {
		if rem, ok := cweRemediation[strings.TrimSpace(c)]; ok {
			return rem
		}
	}
	switch strings.ToLower(tool) {
	case "trivy", "grype", "osv-scanner", "osvscanner", "syft":
		return "Upgrade the affected dependency past the vulnerable version range (or apply the vendor patch); re-scan to confirm the CVE no longer resolves."
	case "operate", "okta":
		return "Apply the identity control named in the finding (enforce MFA, revoke the grant, suspend the account) and re-check the posture."
	case "prowler", "scout-suite", "scoutsuite", "checkov":
		return "Apply the cloud/IaC remediation for the failing control (restrict the public grant, tighten the IAM policy) and re-run the baseline."
	default:
		return "Review the cited evidence and apply the vendor-recommended fix for this finding class, then re-test to confirm closure."
	}
}

// owaspFor returns the OWASP Top 10 (2021) categories the finding's CWEs map to (deduped), or a
// tool-class default for dependency findings that carry no CWE.
func owaspFor(cwes []string, tool string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cwes {
		if cat, ok := cweOWASP[strings.TrimSpace(c)]; ok && !seen[cat] {
			seen[cat] = true
			out = append(out, cat)
		}
	}
	if len(out) == 0 {
		switch strings.ToLower(tool) {
		case "trivy", "grype", "osv-scanner", "osvscanner":
			return []string{"A06:2021 Vulnerable and Outdated Components"}
		}
	}
	return out
}

// narrativeSummary renders the prose executive summary a pentest report opens with, derived
// entirely from the grounded counts (no invented commentary).
func narrativeSummary(r *VAPTReport) string {
	s := r.Summary
	if s.Total == 0 {
		// NOTHING FOUND AND NOTHING TESTED ARE DIFFERENT REPORTS.
		//
		// A scope target that no tool has ever run against produces exactly the same zero as a target
		// that was scanned clean. Rendering both as "no open vulnerabilities … every monitored asset is
		// currently clean" turns an absence of assessment into an assurance — on the one artifact that
		// gets forwarded to an auditor or a prospect.
		if len(r.Untested) == len(r.Scope) && len(r.Scope) > 0 {
			return fmt.Sprintf("**No assessment has run against the scope of %s yet**, so this report states "+
				"nothing about its security. %s %s not been scanned. This is not a clean result — it is an "+
				"empty one. Connect or scan the target, then re-generate this report.",
				r.TenantName, joinTargets(r.Untested), verbFor(len(r.Untested)))
		}
		if len(r.Untested) > 0 {
			return fmt.Sprintf("This assessment of %s found no open vulnerabilities in the targets that were "+
				"scanned. %s %s NOT been assessed, so this report says nothing about %s. Posture across the "+
				"tested scope is rated **%s**.",
				r.TenantName, joinTargets(r.Untested), verbFor(len(r.Untested)),
				pronounFor(len(r.Untested)), s.RiskRating)
		}
		return fmt.Sprintf("This assessment of %s found no open vulnerabilities across the monitored assets. Posture is rated **%s**. TensorShield continues to monitor continuously and will surface any new issue as it appears.",
			r.TenantName, s.RiskRating)
	}
	crit, high := s.BySeverity["critical"], s.BySeverity["high"]
	var lead string
	switch {
	case crit > 0:
		lead = fmt.Sprintf("**%d critical** and %d high-severity issue(s) require immediate attention", crit, high)
	case high > 0:
		lead = fmt.Sprintf("%d high-severity issue(s) should be prioritised", high)
	default:
		lead = "no critical or high-severity issues were found; the remaining items are lower-risk hardening opportunities"
	}
	// Built clause-by-clause rather than one big format string, because each clause has to agree
	// in number with a count that is only known at render time. The old single-string version read
	// "1 are unconfirmed single-tool pattern matches" for a singleton, and spliced the KEV clause
	// mid-sentence producing a two-"and" run-on — both on the executive summary a customer forwards.
	var b strings.Builder
	fmt.Fprintf(&b, "This assessment of %s identified **%d finding(s)** across the monitored assets, giving an overall risk rating of **%s**.%s %s.",
		r.TenantName, s.Total, s.RiskRating, untestedClause(r), capitalize(lead))

	fmt.Fprintf(&b, " Of these, %s", numClause(s.Verified,
		"is tool-confirmed (corroborated or re-verified)",
		"are tool-confirmed (corroborated or re-verified)"))
	if s.Unconfirmed > 0 {
		fmt.Fprintf(&b, " and %s — the latter %s listed after the confirmed findings of the same severity and labelled inline, so no false positive is presented as a proven result",
			numClause(s.Unconfirmed,
				"is an unconfirmed single-tool pattern match to validate before action",
				"are unconfirmed single-tool pattern matches to validate before action"),
			verbIsAre(s.Unconfirmed))
	}
	b.WriteString(".")

	if sentence := kevSentence(s.KEV); sentence != "" {
		fmt.Fprintf(&b, " %s.", sentence)
	}
	if s.FixesReady > 0 {
		fmt.Fprintf(&b, " %s.", numClause(s.FixesReady,
			"has a remediation already prepared", "have a remediation already prepared"))
	}
	return b.String()
}

// numClause renders "1 <singular>" or "N <plural>" so a count and its verb/noun always agree.
func numClause(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// verbIsAre picks the copula for a count.
func verbIsAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// kevSentence is the KEV clause as its own grammatical sentence (was spliced mid-sentence before,
// which broke the surrounding prose). Empty when nothing is KEV-listed.
func kevSentence(kev int) string {
	switch {
	case kev == 0:
		return ""
	case kev == 1:
		return "1 of these is listed in CISA KEV as actively exploited in the wild"
	default:
		return fmt.Sprintf("%d of these are listed in CISA KEV as actively exploited in the wild", kev)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// joinTargets renders scope targets for prose, naming them rather than counting them — "two targets
// were not scanned" sends nobody anywhere; the hostname does.
func joinTargets(t []string) string {
	switch len(t) {
	case 0:
		return ""
	case 1:
		return "`" + t[0] + "`"
	case 2:
		return "`" + t[0] + "` and `" + t[1] + "`"
	}
	out := ""
	for i, x := range t[:len(t)-1] {
		if i > 0 {
			out += ", "
		}
		out += "`" + x + "`"
	}
	return out + " and `" + t[len(t)-1] + "`"
}

func verbFor(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

func pronounFor(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// untestedClause qualifies "across the monitored assets" when some of them were not, in fact,
// assessed. The findings section marks them, but the executive summary is the part that gets read and
// quoted — a rating stated over a scope that was only partly examined has to say so where the rating
// is stated, not only in a list further down.
func untestedClause(r *VAPTReport) string {
	if len(r.Untested) == 0 {
		return ""
	}
	return fmt.Sprintf(" %s %s NOT been assessed and %s not covered by this rating.",
		joinTargets(r.Untested), verbFor(len(r.Untested)), verbIsAre(len(r.Untested)))
}
