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
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Kind       string `json:"kind"` // risk | audit | pentest | policy
	Title      string `json:"title"`
	Detail     string `json:"detail,omitempty"`
	Link       string `json:"link"` // the in-app path to act on it
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
}

// Queue aggregates the pending HITL items across the assigned tenants, each filtered to the
// practitioner's deliverable scope for that tenant. Deterministic order: tenant data in, items out in
// (tenant, kind) order.
func Queue(data []TenantData) []Pending {
	var out []Pending
	for _, td := range data {
		want := scopeSet(td.Scope)
		if want("risk") {
			for _, r := range td.Risks {
				if r.Proposed || r.Status == platform.RiskOpen {
					out = append(out, Pending{td.TenantID, td.TenantName, "risk", r.Title, "awaiting a treatment decision", "/risks"})
				}
			}
		}
		if want("audit") {
			for _, a := range td.Audits {
				pending := 0
				for _, c := range a.Attestations {
					if c.Verdict == platform.AttestPending {
						pending++
					}
				}
				if pending > 0 {
					out = append(out, Pending{td.TenantID, td.TenantName, "audit", a.Framework + " audit", plural(pending, "control") + " awaiting attestation", "/audits"})
				}
			}
		}
		if want("pentest") {
			for _, e := range td.Pentests {
				if e.Status == pentest.StatusComplete && !e.Signed() {
					out = append(out, Pending{td.TenantID, td.TenantName, "pentest", e.Name, "report awaiting sign-off", "/pentest/" + e.ID})
				}
			}
		}
		if want("policy") {
			for _, p := range td.Policies {
				if p.Status == platform.PolicyDraft {
					out = append(out, Pending{td.TenantID, td.TenantName, "policy", p.Name, "draft awaiting publish", "/program"})
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
