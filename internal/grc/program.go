package grc

import (
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Security-program helpers — the vCISO deliverable a consultant otherwise writes: a policy set, the
// team's acknowledgments, and a board-level posture read. The engine can SEED the standard policy set
// (these are industry-standard SOC 2 policy names — grounded, not invented), but ADOPTING / PUBLISHING
// a policy is a named human's judgment call, recorded into the ledger by the API layer.

// starterPolicy is a template the owner adopts. The set mirrors the policies a SOC 2 auditor expects.
type starterPolicy struct {
	Name     string
	Category string
	Summary  string
}

var starterPolicies = []starterPolicy{
	{"Information Security Policy", "Governance", "The overarching commitment to protecting information assets and the program's scope."},
	{"Access Control Policy", "Access Control", "How access is granted, reviewed, and revoked; least-privilege and MFA requirements."},
	{"Acceptable Use Policy", "Governance", "Acceptable use of company systems, data, and accounts by personnel."},
	{"Change Management Policy", "Change Management", "Code review, approval, and release controls for production changes."},
	{"Incident Response Policy", "Incident Response", "How security incidents are detected, escalated, contained, and communicated."},
	{"Business Continuity & Disaster Recovery", "Resilience", "Backup, recovery objectives, and continuity of operations."},
	{"Risk Assessment Policy", "Risk Management", "How risks are identified, scored, and treated (ties to the risk register)."},
	{"Vendor & Third-Party Management", "Vendor Management", "Due diligence and ongoing review of vendors that touch customer data."},
	{"Data Classification & Handling", "Data Protection", "How data is classified, encrypted, retained, and disposed of."},
	{"Vulnerability Management Policy", "Vulnerability Management", "Scanning cadence and remediation SLAs for discovered vulnerabilities."},
}

// StarterPolicies returns the standard policy set as draft policies for the tenant (deterministic;
// stable ids from the name slug so re-seeding updates rather than duplicates). The owner edits +
// publishes each — the engine never publishes on its own.
func StarterPolicies(tenantID string, now time.Time) []platform.Policy {
	out := make([]platform.Policy, 0, len(starterPolicies))
	for _, t := range starterPolicies {
		out = append(out, platform.Policy{
			ID:        "policy-" + slug(t.Name),
			TenantID:  tenantID,
			Name:      t.Name,
			Category:  t.Category,
			Summary:   t.Summary,
			Status:    platform.PolicyDraft,
			Version:   1,
			CreatedAt: now,
		})
	}
	return out
}

// ProgramSummary is the board/owner read of the security program.
type ProgramSummary struct {
	Total          int `json:"total"`
	Published      int `json:"published"`
	Draft          int `json:"draft"`
	TeamSize       int `json:"team_size"`
	FullyAcked     int `json:"fully_acked"`      // published policies acknowledged by the whole team
	AckCoveragePct int `json:"ack_coverage_pct"` // acks / (published × team), 0–100
}

// SummarizeProgram tallies the program for the board view. teamSize is the number of people expected
// to acknowledge (0 ⇒ coverage is not computed). Grounded in the stored policies + their acks.
func SummarizeProgram(policies []platform.Policy, teamSize int) ProgramSummary {
	s := ProgramSummary{Total: len(policies), TeamSize: teamSize}
	totalAcks, publishedCount := 0, 0
	for _, p := range policies {
		if p.Status == platform.PolicyPublished {
			s.Published++
			publishedCount++
			totalAcks += len(p.Acks)
			if teamSize > 0 && len(p.Acks) >= teamSize {
				s.FullyAcked++
			}
		} else {
			s.Draft++
		}
	}
	if teamSize > 0 && publishedCount > 0 {
		denom := publishedCount * teamSize
		s.AckCoveragePct = totalAcks * 100 / denom
		if s.AckCoveragePct > 100 {
			s.AckCoveragePct = 100
		}
	}
	return s
}
