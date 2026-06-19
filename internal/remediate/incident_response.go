package remediate

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// ProposeIncidentResponse is the A-RSP "respond" half of detect-&-respond (agentic-SMB
// spec A-RSP / AGT-3): when a CRITICAL incident opens, the agent PREPARES a breach /
// disclosure communication — a tier-3 (irreversible/legal) DRAFT that a NAMED human must
// edit and sign before it is filed or sent. Because it is T3 it can never auto-apply
// (hitl enforces this), so the agent never sends a regulatory/customer notice on its own.
//
// Non-critical incidents return false: they flow through the normal per-finding remediation
// path, not breach comms. The draft is grounded in the real incident (its rule + the
// finding that opened it) and is explicit that its claims are unverified until a human
// confirms them — no hallucinated breach facts.
func ProposeIncidentResponse(inc platform.Incident, idgen func() string) (platform.Action, bool) {
	if !strings.EqualFold(inc.Severity, string(types.SeverityCritical)) {
		return platform.Action{}, false
	}
	return platform.Action{
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
	}, true
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
