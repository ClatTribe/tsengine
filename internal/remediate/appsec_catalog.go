package remediate

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Respond breadth for the APPSEC surfaces — web_application, api, container_image.
//
// THE GAP THIS CLOSES. remediate.Propose routed only three asset types to a real fix: repository (a
// PR), cloud_account (the cloud catalog + three live writes) and workspace (identity runbooks + a
// live suspend). Everything else fell to the `default:` branch — a ticket titled "review <finding>"
// carrying nothing but the finding's own description. So five of eight asset types had no fix path,
// and the two where the product is STRONGEST offensively were among them: the AI Pentester proves an
// SQLi by exploiting it (XBOW 85.6%, above published SOTA), hands the proven finding to
// remediate.Propose, and the proposal is "review this". The best evidence in the product met the
// weakest response, which is the shape ADR 0024 exists to police pointed at Respond instead of Detect.
//
// Container image is the sharpest case: a container CVE has a MECHANICAL fix — upgrade the package,
// or move the base image — and the scanners already report the exact fixed version.
//
// Same contract as cloudFixCatalog, deliberately: a machine-readable remediation_type plus a
// specific, copy-pasteable runbook, so a class can be PROMOTED to a live HITL-gated mutation with one
// entry the moment a write path exists. None of these is live-writable today — that is the honest
// gate, and it is why these ride as tier-1 tickets rather than ActApplyConfig.
//
// Grounding (§10): every matcher reads ONLY the finding's own CWE, rule id, title, description and
// endpoint. The runbook names the finding's OWN resource and cites a version ONLY when the scanner
// really reported one — an upgrade target we invented is worse than none, because it is actionable
// and wrong. A finding matching no class returns ok=false and keeps today's generic ticket, so an
// unrecognised class is never mislabeled. §13 holds: this is remediation glue over an already
// grounded finding, not a new detector.
const (
	rtypePackageUpgrade     = "package_upgrade"           // a dependency/OS package CVE with a known fixed version
	rtypeBaseImageUpgrade   = "base_image_upgrade"        // an image CVE with no per-package fix available
	rtypeContainerHardening = "container_hardening"       // dockle/CIS Dockerfile posture (root user, secrets in ENV)
	rtypeImageSigning       = "image_signing"             // cosign: unsigned / unverifiable image
	rtypeParameterizeQuery  = "parameterize_query"        // CWE-89 SQL injection
	rtypeEncodeOutput       = "encode_output"             // CWE-79 XSS
	rtypeSSRFAllowlist      = "ssrf_allowlist"            // CWE-918 SSRF
	rtypeRedirectAllowlist  = "redirect_allowlist"        // CWE-601 open redirect
	rtypePathCanonicalize   = "path_canonicalization"     // CWE-22/23/98 traversal / LFI
	rtypeAvoidShellExec     = "avoid_shell_exec"          // CWE-77/78 command injection
	rtypeEnforceObjectAuthz = "enforce_object_authz"      // CWE-639/862/863 BOLA / BFLA
	rtypeRotateDefaultCreds = "rotate_default_credential" // CWE-798/1392 default or hardcoded credential
	rtypeRemoveExposedFile  = "remove_exposed_artifact"   // CWE-200/538 exposed .env / .git / backup
	rtypeSecurityHeaders    = "set_security_headers"      // CWE-693/1021 missing CSP / HSTS / frame-options
	rtypeTLSHardening       = "tls_hardening"             // CWE-326/327 weak TLS
	rtypeGraphQLIntrospect  = "disable_graphql_introspection"
)

// appsecMatcher is one class: a grounded predicate over the finding's own text plus the class's
// remediation_type and a runbook builder naming the exact fix for THAT finding's resource.
type appsecMatcher struct {
	rtype   string
	match   func(f types.Finding, hay string) bool
	runbook func(f types.Finding) string
}

// hasCWE reports whether the finding carries any of these CWE ids. CWE is the most reliable signal
// available here — it survives tool renames and template churn, which is why it is checked before the
// text heuristics rather than instead of them.
func hasCWE(f types.Finding, ids ...string) bool {
	for _, got := range f.CWE {
		g := strings.ToUpper(strings.TrimSpace(got))
		for _, want := range ids {
			if g == want {
				return true
			}
		}
	}
	return false
}

// pkgCoord returns the package coordinate and the scanner-reported fixed version, if the scanner
// really reported them (grype/syft/trivy set these ToolArgs). Both may be empty, and the runbooks
// must read correctly when they are — inventing an upgrade target is worse than admitting we do not
// have one, because a wrong version is actionable.
func pkgCoord(f types.Finding) (pkg, installed, fixed string) {
	return f.ToolArgs["pkg"], f.ToolArgs["installed_version"], f.ToolArgs["fixed_version"]
}

// upgradeLine renders the concrete upgrade instruction when the scanner named a fixed version, and an
// honest "no fixed version was reported" line when it did not.
func upgradeLine(f types.Finding) string {
	pkg, installed, fixed := pkgCoord(f)
	switch {
	case pkg != "" && fixed != "":
		at := ""
		if installed != "" {
			at = " (currently " + installed + ")"
		}
		return "Upgrade " + pkg + at + " to " + fixed + " or later, then rebuild and re-scan the image."
	case pkg != "":
		return "The scanner did not report a fixed version for " + pkg + ". Check the upstream advisory " +
			"for a patched release; if none exists, remove or replace the package, or apply the vendor's " +
			"documented mitigation. Do NOT assume a later tag fixes it."
	default:
		return "The scanner did not report a package coordinate for this finding, so the upgrade target " +
			"is unknown. Resolve the affected component from the image SBOM before acting."
	}
}

// appsecCatalog is ordered MOST-SPECIFIC first — the first match wins, so a package CVE is tested
// before the broad container-hardening class and BOLA before the generic authz text.
var appsecCatalog = []appsecMatcher{
	{
		rtype: rtypePackageUpgrade,
		match: func(f types.Finding, hay string) bool {
			_, _, fixed := pkgCoord(f)
			return fixed != "" && (strings.Contains(hay, "cve-") || strings.Contains(hay, "ghsa-") || anyOf(hay, "grype", "trivy", "vulnerab"))
		},
		runbook: func(f types.Finding) string {
			return "Patch the vulnerable package in " + resourceOf(f) + ".\n  " + upgradeLine(f) +
				"\n  Rebuild the image from a clean layer cache so the old package is not carried forward, " +
				"then re-scan to confirm the CVE is gone."
		},
	},
	{
		rtype: rtypeBaseImageUpgrade,
		match: func(f types.Finding, hay string) bool {
			_, _, fixed := pkgCoord(f)
			return fixed == "" && strings.Contains(hay, "cve-") &&
				anyOf(hay, "grype", "trivy", "image", "layer", "debian", "alpine", "ubuntu", "distro", "os package")
		},
		runbook: func(f types.Finding) string {
			return "No per-package fix is available for this CVE in " + resourceOf(f) + ", so remediate at the " +
				"base image.\n  " + upgradeLine(f) +
				"\n  Move to a newer or slimmer base (e.g. a current -slim/alpine/distroless tag), rebuild, and " +
				"re-scan. If the CVE persists on every available base, record it as an accepted risk with the " +
				"reason — a CVE nobody can fix is a decision, not a silent omission."
		},
	},
	{
		rtype: rtypeContainerHardening,
		match: func(f types.Finding, hay string) bool {
			return anyOf(hay, "dockle", "cis-di-", "runs as root", "root user", "no healthcheck",
				"secret in env", "credential in env", "sensitive data in env", "add instead of copy", "latest tag")
		},
		runbook: func(f types.Finding) string {
			return "Harden the image build for " + resourceOf(f) + ".\n" +
				"  Root user: add a non-root USER (and a matching --chown on COPY) in the Dockerfile.\n" +
				"  Secrets in ENV/ARG: they persist in the image layers — remove them, pass secrets at RUNTIME " +
				"(env at deploy, a mounted secret, or BuildKit --mount=type=secret), and ROTATE anything that " +
				"was baked in, because the old layers may already be published.\n" +
				"  Pin the base tag to a digest rather than :latest so the build is reproducible."
		},
	},
	{
		rtype: rtypeImageSigning,
		match: func(f types.Finding, hay string) bool {
			return anyOf(hay, "cosign", "unsigned", "signature", "attestation") && anyOf(hay, "image", "registry", "digest")
		},
		runbook: func(f types.Finding) string {
			return "Sign " + resourceOf(f) + " and enforce verification at deploy.\n" +
				"  Sign in CI: cosign sign --key <key|keyless-OIDC> <image>@<digest>\n" +
				"  Verify before run: cosign verify --certificate-identity <ci-identity> --certificate-oidc-issuer <issuer> <image>\n" +
				"  Enforce it in the cluster (an admission policy) so an unsigned image cannot be deployed — " +
				"signing without enforcement changes nothing an attacker has to work around."
		},
	},
	{
		rtype: rtypeParameterizeQuery,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-89") || anyOf(hay, "sql injection", "sqli", "sqlmap")
		},
		runbook: func(f types.Finding) string {
			return "Fix the SQL injection reachable at " + resourceOf(f) + ".\n" +
				"  Replace the concatenated query with a PARAMETERISED statement (bind variables / prepared " +
				"statement); an ORM's raw-query escape hatch counts as concatenation.\n" +
				"  Allow-list anything that cannot be a bind parameter (table and column names, ORDER BY, LIMIT).\n" +
				"  Then reduce blast radius: the database user behind this endpoint should hold only the rights " +
				"it needs. A WAF rule is a stopgap, not the fix — re-test the endpoint after the code change."
		},
	},
	{
		rtype: rtypeEncodeOutput,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-79", "CWE-80") || anyOf(hay, "cross-site scripting", "xss", "dalfox")
		},
		runbook: func(f types.Finding) string {
			return "Fix the cross-site scripting reachable at " + resourceOf(f) + ".\n" +
				"  Encode on OUTPUT for the context the value lands in (HTML body, attribute, JS, URL) rather " +
				"than sanitising on input — the correct encoding depends on where it is rendered.\n" +
				"  Prefer the framework's auto-escaping template path; audit every place the escape is bypassed " +
				"(dangerouslySetInnerHTML, |safe, v-html, innerHTML).\n" +
				"  Add a Content-Security-Policy that forbids inline script, so the next missed sink is not " +
				"immediately exploitable."
		},
	},
	{
		rtype: rtypeSSRFAllowlist,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-918") || anyOf(hay, "server-side request forgery", "ssrf")
		},
		runbook: func(f types.Finding) string {
			return "Fix the server-side request forgery reachable at " + resourceOf(f) + ".\n" +
				"  ALLOW-LIST the destinations this feature may reach (scheme, host, port); a deny-list of " +
				"private ranges is bypassable via redirects, DNS rebinding and alternate IP encodings.\n" +
				"  Re-validate the destination AFTER each redirect, and disable redirect-following if you can.\n" +
				"  On cloud hosts, require IMDSv2 (or block link-local 169.254.169.254 egress) so an SSRF cannot " +
				"read instance credentials — that is what turns this finding into a cloud compromise."
		},
	},
	{
		rtype: rtypeRedirectAllowlist,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-601") || anyOf(hay, "open redirect", "unvalidated redirect")
		},
		runbook: func(f types.Finding) string {
			return "Fix the open redirect at " + resourceOf(f) + ".\n" +
				"  Do not redirect to a caller-supplied absolute URL. Accept a relative path, or map an opaque " +
				"key to a destination held server-side.\n" +
				"  If an absolute URL is unavoidable, allow-list the exact hosts and reject anything else — " +
				"prefix checks are bypassable (evil-example.com matches a naive \"starts with example.com\")."
		},
	},
	{
		rtype: rtypePathCanonicalize,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-22", "CWE-23", "CWE-98") ||
				anyOf(hay, "path traversal", "directory traversal", "local file inclusion", "lfi", "../")
		},
		runbook: func(f types.Finding) string {
			return "Fix the path traversal reachable at " + resourceOf(f) + ".\n" +
				"  Resolve the requested path to its CANONICAL absolute form and verify it is still inside the " +
				"intended directory; check after resolving, since stripping \"../\" can be defeated by encoding " +
				"and by symlinks.\n" +
				"  Better where possible: never build a filesystem path from user input — map an opaque id to a " +
				"known file server-side."
		},
	},
	{
		rtype: rtypeAvoidShellExec,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-77", "CWE-78") || anyOf(hay, "command injection", "os command", "rce via command")
		},
		runbook: func(f types.Finding) string {
			return "Fix the command injection reachable at " + resourceOf(f) + ".\n" +
				"  Invoke the binary DIRECTLY with an argument vector (execve-style) instead of building a shell " +
				"string — no shell, no metacharacters to escape.\n" +
				"  If a shell is genuinely required, allow-list the permitted values rather than escaping them.\n" +
				"  Drop the process's privileges so a missed sink is not immediately root."
		},
	},
	{
		rtype: rtypeEnforceObjectAuthz,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-639", "CWE-862", "CWE-863", "CWE-285") ||
				anyOf(hay, "bola", "bfla", "idor", "broken object level", "broken function level", "insecure direct object")
		},
		runbook: func(f types.Finding) string {
			return "Fix the broken authorization at " + resourceOf(f) + ".\n" +
				"  Check ownership SERVER-SIDE on every request: the object id from the request must be scoped to " +
				"the caller's identity from the SESSION, never to a tenant/user id also supplied by the caller.\n" +
				"  Enforce it in one shared place (a policy layer or a scoped query) rather than per handler — " +
				"per-handler checks are why one endpoint is always missed.\n" +
				"  Unguessable ids are not a fix; they are a delay. Re-test with two real accounts after the change."
		},
	},
	{
		rtype: rtypeRotateDefaultCreds,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-798", "CWE-1392", "CWE-521") ||
				anyOf(hay, "default credential", "default login", "default password", "hardcoded credential", "weak password")
		},
		runbook: func(f types.Finding) string {
			return "Replace the default/known credential on " + resourceOf(f) + ".\n" +
				"  Rotate it now and treat the old value as COMPROMISED — it is published in vendor docs and in " +
				"every scanner's wordlist, so assume it has been tried.\n" +
				"  Disable the default account where the product allows it, require MFA on the replacement, " +
				"and restrict the management interface to a trusted network rather than the public internet.\n" +
				"  Check the logs for successful logins with the old credential before rotation."
		},
	},
	{
		rtype: rtypeRemoveExposedFile,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-200", "CWE-538", "CWE-540", "CWE-548") ||
				anyOf(hay, "exposed .env", "/.git/", ".git/config", "backup file", "directory listing",
					"exposed configuration", "information disclosure", "phpinfo")
		},
		runbook: func(f types.Finding) string {
			return "Remove the exposed artifact at " + resourceOf(f) + ".\n" +
				"  Stop serving it (delete it from the web root / deny the path at the server or CDN) and disable " +
				"directory listing.\n" +
				"  ROTATE every secret the file could have disclosed. The file was publicly reachable, so treat " +
				"its contents as leaked regardless of whether you can see a request for it in the logs — absence " +
				"of a log entry is not evidence nobody read it.\n" +
				"  Fix the pipeline that shipped it, or it returns on the next deploy."
		},
	},
	{
		rtype: rtypeGraphQLIntrospect,
		match: func(f types.Finding, hay string) bool {
			return anyOf(hay, "introspection", "graphql schema exposed", "inql")
		},
		runbook: func(f types.Finding) string {
			return "Disable GraphQL introspection in production at " + resourceOf(f) + ".\n" +
				"  Turn introspection off in the server config for the production environment only, so " +
				"development tooling keeps working.\n" +
				"  Pair it with query depth/complexity limits and disable any GraphiQL/playground route — " +
				"introspection off is reconnaissance friction, not authorization. The authorization checks on " +
				"each resolver are the actual control."
		},
	},
	{
		rtype: rtypeTLSHardening,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-326", "CWE-327", "CWE-757") ||
				anyOf(hay, "tls 1.0", "tls 1.1", "sslv3", "weak cipher", "expired certificate", "self-signed",
					"certificate expired", "no https", "http instead of https")
		},
		runbook: func(f types.Finding) string {
			return "Harden TLS on " + resourceOf(f) + ".\n" +
				"  Serve TLS 1.2+ (prefer 1.3), disable SSLv3/TLS 1.0/1.1 and the weak cipher suites, and renew " +
				"or replace an expired/self-signed certificate with one from a trusted CA.\n" +
				"  Redirect HTTP to HTTPS and send HSTS once the redirect is verified working on every hostname.\n" +
				"  Automate renewal — an expiry finding usually means the renewal, not the certificate, is broken."
		},
	},
	{
		rtype: rtypeSecurityHeaders,
		match: func(f types.Finding, hay string) bool {
			return hasCWE(f, "CWE-693", "CWE-1021", "CWE-1275") ||
				anyOf(hay, "content-security-policy", "missing csp", "x-frame-options", "clickjack",
					"strict-transport-security", "missing security header", "samesite", "x-content-type-options")
		},
		runbook: func(f types.Finding) string {
			return "Set the missing response security headers on " + resourceOf(f) + ".\n" +
				"  Content-Security-Policy (start in report-only, then enforce), X-Content-Type-Options: nosniff, " +
				"and a frame ancestors policy (CSP frame-ancestors, or X-Frame-Options for old clients).\n" +
				"  Strict-Transport-Security only once HTTPS works on every hostname — sending it earlier locks " +
				"clients out of a site that cannot yet serve them.\n" +
				"  Set cookies Secure + HttpOnly + SameSite. These are DEFENCE IN DEPTH: they reduce the impact " +
				"of an injection, they do not remove one."
		},
	},
}

// appsecFixCatalog returns the class-correct remediation_type and a specific runbook for a
// web_application / api / container_image finding. ok=false → no class matched → the caller keeps the
// generic ticket, so an unrecognised finding is never given a confident wrong fix.
func appsecFixCatalog(f types.Finding) (rtype, runbook string, ok bool) {
	hay := strings.ToLower(f.RuleID + " " + f.Tool + " " + f.Title + " " + f.Description + " " + f.Endpoint)
	for _, m := range appsecCatalog {
		if m.match(f, hay) {
			return m.rtype, m.runbook(f), true
		}
	}
	return "", "", false
}

// appsecRunbookRemediations is every remediation_type this catalog can emit. None has a live
// connector write path today, so all of them ride as tier-1 tickets carrying the steps. Derived from
// the catalog so a newly-added class is included automatically; when a class gains a live write, move
// it out and give it a connector.Apply case — the same promotion path S3 block-public-access took.
var appsecRunbookRemediations = func() map[string]bool {
	m := make(map[string]bool, len(appsecCatalog))
	for _, c := range appsecCatalog {
		m[c.rtype] = true
	}
	return m
}()
