package remediate

// Mitigate now, patch later (ADR 0025 follow-on / CTEM mobilization).
//
// THE GAP. Both fix catalogs propose THE FIX, and for the appsec classes the fix is a CODE CHANGE:
// parameterise the query, encode the output, allow-list the destination. That is the right answer and
// it lands on a release cycle. Meanwhile the exposure is live. The category's framing is that risk
// reduction should start immediately rather than when the patch is ready — and until now the only
// acknowledgement of that anywhere in the remediation layer was a sentence of prose inside one
// runbook ("A WAF rule is a stopgap, not the fix"), true and machine-invisible.
//
// SCOPE, and it is the honest one: an interim mitigation is offered ONLY where the fix is a code
// change and an EDGE or RUNTIME control can reduce the exposure today. Classes whose fix is itself a
// config change (rotate the credential, block public access, narrow the security group) get nothing
// here, because for those "mitigate now" and "fix" are the same act and offering a second-best
// version would be noise.
//
// TWO REFUSALS make it safe to show:
//
//  1. A MITIGATION IS NOT A FIX. It never marks anything resolved, never downgrades severity, never
//     suppresses. The finding stays open, the re-test still has to prove closure, and the text says
//     so — because a customer who applies a WAF rule and sees the finding disappear will believe the
//     bug is gone, which is the exact false-confidence §10 exists to prevent.
//  2. WE DO NOT CLAIM THEY HAVE THE CONTROL. Without a control-plane integration we do not know
//     whether this customer runs a WAF, an egress proxy or a CDN. So every mitigation is phrased
//     conditionally and names the control it needs. Asserting an available control we never observed
//     would be the same overclaim as a scan we never ran.
const (
	mitigateAtEdge    = "edge_control"         // a WAF / CDN / reverse-proxy rule in front of the app
	mitigateEgress    = "egress_restriction"   // deny outbound to the resource the bug reaches for
	mitigateHeaders   = "response_header"      // a header the edge can inject today
	mitigateBlockPath = "block_path"           // stop serving a path outright
	mitigatePrivilege = "reduce_privilege"     // shrink what the vulnerable code can do when abused
	mitigateRateLimit = "rate_limit_and_alert" // slow abuse and make it visible while the fix lands
)

// interimMitigation returns something that reduces exposure TODAY for a remediation class whose real
// fix is a code change. Keyed on the remediation_type the catalog already decided, so this adds no
// second matcher that could disagree with the first.
//
// ok=false means no honest interim exists for this class — the caller then offers none rather than
// inventing a weaker-sounding version of the fix.
func interimMitigation(rtype string) (mtype, steps string, ok bool) {
	const caveat = "\n\nThis does NOT fix the vulnerability and does not close this finding. It " +
		"reduces exposure while the code change lands; the finding stays open and the re-test still " +
		"has to prove the fix closed it."
	switch rtype {
	case rtypeParameterizeQuery:
		return mitigateAtEdge, "If you run a WAF or reverse proxy in front of this endpoint, enable its " +
			"SQL-injection ruleset for that path now, and separately revoke any rights the application's " +
			"database user does not need (DROP, file access, other schemas) so a successful injection " +
			"reaches less." + caveat, true
	case rtypeEncodeOutput:
		return mitigateHeaders, "If you can set response headers at the edge, ship a Content-Security-" +
			"Policy that forbids inline script for this route — start in report-only to find breakage, " +
			"then enforce. A missed sink stops being immediately exploitable." + caveat, true
	case rtypeSSRFAllowlist:
		return mitigateEgress, "Deny this service's outbound access to the cloud metadata endpoint " +
			"(169.254.169.254) and to internal ranges it has no reason to reach, at the security group, " +
			"egress proxy or service mesh. On AWS, requiring IMDSv2 also blocks the credential-theft " +
			"path that turns an SSRF into a cloud compromise." + caveat, true
	case rtypeRedirectAllowlist:
		return mitigateAtEdge, "If you run a WAF or reverse proxy, add a rule on this route that rejects " +
			"a redirect parameter pointing at any host outside your own domains." + caveat, true
	case rtypePathCanonicalize:
		return mitigateAtEdge, "Enable the path-traversal ruleset on your WAF or reverse proxy for this " +
			"route. Treat it as friction, not a boundary — encodings bypass these rules routinely." + caveat, true
	case rtypeAvoidShellExec:
		return mitigatePrivilege, "Drop the privileges of the process behind this endpoint now — run it " +
			"as a non-root user, remove capabilities it does not use, and restrict its outbound network " +
			"access — so a successful injection achieves less." + caveat, true
	case rtypeRemoveExposedFile:
		return mitigateBlockPath, "Stop serving this path immediately at the CDN, load balancer or web " +
			"server, ahead of removing the file from the build. Rotate every secret it could have " +
			"disclosed regardless: it was publicly reachable, so treat the contents as leaked." + caveat, true
	case rtypeEnforceObjectAuthz:
		return mitigateRateLimit, "Rate-limit this route per session and alert on sequential or " +
			"high-volume object access, so enumeration is slowed and visible while the ownership check " +
			"is added. This does not stop a targeted request for one known id." + caveat, true
	}
	return "", "", false
}
