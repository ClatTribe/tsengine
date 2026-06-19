package remediate

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ProposeIncidentResponse is the A-RSP "respond" half of detect-&-respond (agentic-SMB
// spec A-RSP / AGT-3). When a CRITICAL incident opens, the agent prepares TWO responses:
//
//  1. CONTAINMENT — a tier-2 (consequential, human-gated) action recommending how to stop
//     the bleeding now (suspend the account, restrict the resource, block the endpoint),
//     targeting the affected entity. It is gated, so a human approves before anything is
//     applied — the autonomous team proposes containment; a person decides.
//  2. DISCLOSURE — a tier-3 (irreversible/legal) breach-comms DRAFT a NAMED human must edit
//     and sign before it is filed or sent. T3 can never auto-apply, so the agent never
//     sends a regulatory/customer notice on its own.
//
// Non-critical incidents return (nil,false): they flow through the normal per-finding
// remediation path. Both responses are grounded in the real incident (its rule + the
// finding that opened it + the entity in its key) — no hallucinated facts; containment is a
// recommendation a human gates, disclosure is explicitly unverified until a human confirms.
func ProposeIncidentResponse(inc platform.Incident, idgen func() string) ([]platform.Action, bool) {
	if !strings.EqualFold(inc.Severity, string(types.SeverityCritical)) {
		return nil, false
	}
	return []platform.Action{
		proposeContainment(inc, idgen),
		{
			ID: id("act", idgen), TenantID: inc.TenantID, FindingID: inc.FindingID,
			Kind: platform.ActDraftNotification, Tier: platform.TierIrreversible, Status: platform.ActProposed,
			Title: "Draft breach disclosure: " + inc.Title,
			Payload: map[string]any{
				"incident_id":      inc.ID,
				"rule_id":          inc.RuleID,
				"severity":         inc.Severity,
				"remediation_type": "breach_notification",
				"draft":            draftDisclosure(inc),
			},
		},
	}, true
}

// proposeContainment builds the tier-2 gated containment recommendation for a critical
// incident. It is GATED (tier-2 → a human approves before anything happens) and delivered
// as a containment-runbook ticket: it carries a machine-readable remediation_type+target
// (so a future live containment connector can promote it to a real apply, exactly like the
// identity runbooks promote to an Okta suspend) plus a human-readable runbook. Filed via the
// ticket path so it delivers gracefully without an incident-level connection. The step is
// chosen from the incident's class (identity / cloud / web-api) and names the affected entity
// (the endpoint half of inc.Key).
func proposeContainment(inc platform.Incident, idgen func() string) platform.Action {
	target := entityFromKey(inc.Key)
	return platform.Action{
		ID: id("act", idgen), TenantID: inc.TenantID, FindingID: inc.FindingID,
		Kind: platform.ActFileTicket, Tier: platform.GateTier, Status: platform.ActProposed,
		Title: "Contain: " + inc.Title,
		Payload: map[string]any{
			"incident_id":      inc.ID,
			"rule_id":          inc.RuleID,
			"severity":         inc.Severity,
			"remediation_type": "containment",
			"target":           target,
			"runbook":          containmentRunbook(inc.RuleID, target),
		},
	}
}

// entityFromKey extracts the affected entity from an incident key ("<rule_id>|<endpoint>"),
// falling back to a generic phrase when the key carries no endpoint.
func entityFromKey(key string) string {
	if i := strings.Index(key, "|"); i >= 0 && i+1 < len(key) {
		if ep := strings.TrimSpace(key[i+1:]); ep != "" {
			return ep
		}
	}
	return "the affected asset"
}

// containmentRunbook returns the class-specific containment step, grounded by the rule id.
func containmentRunbook(ruleID, target string) string {
	r := strings.ToLower(ruleID)
	switch {
	case strings.Contains(r, "operate") || strings.Contains(r, "okta") || strings.Contains(r, "mfa") ||
		strings.Contains(r, "oauth") || strings.Contains(r, "account"):
		return "Suspend the affected account and revoke its active sessions/tokens, then require re-enrollment: " + target
	case strings.Contains(r, "prowler") || strings.Contains(r, "scoutsuite") || strings.Contains(r, "s3") ||
		strings.Contains(r, "iam") || strings.Contains(r, "aws") || strings.Contains(r, "gcp") || strings.Contains(r, "azure"):
		return "Restrict the exposed resource — remove public/over-broad grants and quarantine it — pending remediation: " + target
	case strings.Contains(r, "nuclei") || strings.Contains(r, "sqlmap") || strings.Contains(r, "dalfox") ||
		strings.Contains(r, "xss") || strings.Contains(r, "sqli") || strings.Contains(r, "rce") || strings.Contains(r, "http"):
		return "Block the affected endpoint (a WAF rule or take it offline) until the fix ships: " + target
	default:
		return "Isolate or restrict access to the affected asset pending remediation: " + target
	}
}

// draftDisclosure renders the human-reviewable disclosure draft from a confirmed incident.
// It deliberately leads with "DRAFT — unverified" and a checklist so a human never sends
// agent-asserted breach facts without confirming scope, obligations, and deadlines.
func draftDisclosure(inc platform.Incident) string {
	opened := inc.OpenedAt.Format("2006-01-02 15:04 MST")
	return fmt.Sprintf(`DRAFT — security incident disclosure. Review, edit, and SIGN before sending.

Automated continuous monitoring detected and confirmed a critical security issue:

  • Issue:    %s
  • Rule:     %s
  • Severity: %s
  • Opened:   %s
  • Evidence: finding %s

Before any external communication, a named human MUST:
  1. Confirm scope and affected parties with the security lead.
  2. Determine regulatory obligations and deadlines (e.g. GDPR 72h, India DPDP, US state
     breach laws) for the confirmed facts.
  3. Edit this draft to match what is verified — do NOT send unverified claims.

Prepared by the autonomous security agent; it requires a named human signature before it
is filed or sent. The agent does not send regulatory or customer communications on its own.`,
		inc.Title, inc.RuleID, inc.Severity, opened, inc.FindingID)
}
