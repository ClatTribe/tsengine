// Package practitioner computes the cross-tenant work queue for an expert who provides the
// human-in-the-loop across a book of client tenants — the MSP's expert or our managed delivery
// expert. It is pure + grounded: it surfaces only the HITL items that are genuinely pending (a risk
// awaiting a decision, a control awaiting attestation, a complete pentest awaiting sign-off, a draft
// policy awaiting publish). The CALLER is responsible for the cross-tenant authorization — this
// package only aggregates already-authorized per-tenant data, so it never broadens tenant isolation.
package practitioner

import (
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Pending is one HITL item awaiting the practitioner, across all the tenants they serve.
type Pending struct {
	TenantID   string   `json:"tenant_id"`
	TenantName string   `json:"tenant_name"`
	Kind       string   `json:"kind"`               // action | risk | audit | pentest | policy
	ItemID     string   `json:"item_id"`            // the underlying entity id — lets the operator act on it from the desk
	Controls   []string `json:"controls,omitempty"` // for audits: the control ids still awaiting attestation (act-on-behalf)
	Title      string   `json:"title"`
	Detail     string   `json:"detail,omitempty"`
	Link       string   `json:"link"` // the in-app path to act on it
	// Diff is the code change a remediation would apply, so the desk can show WHAT is being approved
	// rather than only its title. Empty for the ceremonies that change no code.
	Diff string `json:"diff,omitempty"`
	// Feedback is a reviewer's "change this" note on an action that was sent back — it belongs in the
	// queue so a returned proposal reads as part of a thread, not as a fresh item.
	Feedback string `json:"feedback,omitempty"`
}

// TenantData is one assigned tenant's HITL-relevant state. The caller loads it tenant-scoped (it is
// already authorized to read each of these for the tenant) and hands it to Queue. Scope is the
// practitioner's deliverable scope FOR THIS tenant (empty = all).
type TenantData struct {
	TenantID   string
	TenantName string
	Scope      []string
	Risks      []platform.Risk
	Audits     []platform.AuditEngagement
	Pentests   []pentest.Engagement
	Policies   []platform.Policy
	// Actions are the remediations queued at the HITL desk. This was the conspicuous omission: the
	// desk aggregated the four judgement ceremonies (risk, audit, pentest sign-off, policy publish)
	// but not the one a practitioner meets MOST OFTEN — "should this fix be applied?". The result was
	// two half-views of the same job: the operator's queue had everything except approvals, and the
	// tenant's inbox had approvals and nothing else. Neither answered "what needs a human right now".
	Actions []platform.Action
}

// Queue aggregates the pending HITL items across the assigned tenants, each filtered to the
// practitioner's deliverable scope for that tenant. Deterministic order: tenant data in, items out in
// (tenant, kind) order.
func Queue(data []TenantData) []Pending {
	var out []Pending
	for _, td := range data {
		want := scopeSet(td.Scope)
		// Remediation approvals lead, because they are the item a practitioner meets most often and
		// the only one with a real deadline attached — a queued fix is a vulnerability still open.
		if want("action") {
			for _, a := range td.Actions {
				detail, ok := actionDetail(a)
				if !ok {
					continue
				}
				out = append(out, Pending{
					TenantID: td.TenantID, TenantName: td.TenantName, Kind: "action", ItemID: a.ID,
					Title: actionTitle(a), Detail: detail, Link: "/inbox",
					Diff: a.Diff, Feedback: a.Feedback,
				})
			}
		}
		if want("risk") {
			for _, r := range td.Risks {
				if r.Proposed || r.Status == platform.RiskOpen {
					out = append(out, Pending{TenantID: td.TenantID, TenantName: td.TenantName, Kind: "risk", ItemID: r.ID, Title: r.Title, Detail: "awaiting a treatment decision", Link: "/risks"})
				}
			}
		}
		if want("audit") {
			for _, a := range td.Audits {
				var pendingControls []string
				for _, c := range a.Attestations {
					if c.Verdict == platform.AttestPending {
						pendingControls = append(pendingControls, c.ControlID)
					}
				}
				if len(pendingControls) > 0 {
					out = append(out, Pending{TenantID: td.TenantID, TenantName: td.TenantName, Kind: "audit", ItemID: a.ID, Controls: pendingControls, Title: a.Framework + " audit", Detail: plural(len(pendingControls), "control") + " awaiting attestation", Link: "/audits"})
				}
			}
		}
		if want("pentest") {
			for _, e := range td.Pentests {
				if e.Status == pentest.StatusComplete && !e.Signed() {
					out = append(out, Pending{TenantID: td.TenantID, TenantName: td.TenantName, Kind: "pentest", ItemID: e.ID, Title: e.Name, Detail: "report awaiting sign-off", Link: "/pentest/" + e.ID})
				}
			}
		}
		if want("policy") {
			for _, p := range td.Policies {
				if p.Status == platform.PolicyDraft {
					out = append(out, Pending{TenantID: td.TenantID, TenantName: td.TenantName, Kind: "policy", ItemID: p.ID, Title: p.Name, Detail: "draft awaiting publish", Link: "/program"})
				}
			}
		}
	}
	return out
}

// scopeSet returns a predicate for whether a deliverable kind is in the practitioner's scope. Empty
// scope = everything. "vciso" is an alias covering the vCISO deliverables (risk register + program).
func scopeSet(scope []string) func(kind string) bool {
	if len(scope) == 0 {
		return func(string) bool { return true }
	}
	allowed := map[string]bool{}
	for _, s := range scope {
		switch s {
		case "vciso":
			allowed["risk"] = true
			allowed["policy"] = true
		case "security":
			// A security-scoped practitioner owns the remediation queue and the pentest sign-off —
			// the hands-on half, as distinct from the vCISO judgement half above.
			allowed["action"] = true
			allowed["pentest"] = true
		default:
			allowed[s] = true
		}
	}
	return func(kind string) bool { return allowed[kind] }
}

func plural(n int, noun string) string {
	s := itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// actionDetail describes what the practitioner is being asked for, and reports whether the action
// belongs in the queue at all.
//
// Only two states are genuinely awaiting a person:
//
//	pending_approval   nobody has looked at it yet
//	changes_requested  a reviewer sent it back and it is waiting on a revised proposal
//
// Everything else — proposed (not yet gated), approved, applied, rejected — is either the agent's turn
// or already settled, and listing it would pad the desk with work that is not work. A queue that shows
// resolved items is a queue people stop reading.
func actionDetail(a platform.Action) (string, bool) {
	switch a.Status {
	case platform.ActPendingApproval:
		if a.Tier >= platform.TierIrreversible {
			return "irreversible — needs a named signature", true
		}
		return "fix awaiting your approval", true
	case platform.ActChangesRequested:
		return "sent back for changes — awaiting a revised proposal", true
	}
	return "", false
}

// actionTitle prefers the action's own title and falls back to its kind, so a row is never blank.
func actionTitle(a platform.Action) string {
	if a.Title != "" {
		return a.Title
	}
	return a.Kind
}
