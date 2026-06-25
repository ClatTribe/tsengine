package grc

import (
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Risk register — the vCISO judgment artifact a security consultant maintains. The engine can only
// PROPOSE candidate risks, grounded in real findings (§10): each candidate clusters findings by a
// coarse category, cites their ids, and sets a *starting* likelihood/impact from the evidence. The
// engine never decides treatment — accepting/transferring/avoiding residual risk is a human judgment
// call (HITL), recorded with a named owner + rationale + ledger signature by the API layer.
//
// CandidateRisks is deterministic (stable ids from the category slug) so re-seeding a tenant updates
// the same candidate rows instead of duplicating them, and never overwrites a risk a human has
// already decided (the caller checks Proposed/DecidedBy before upserting).

// candidateFloor is the severity at/above which a finding seeds a candidate risk. Below this, a
// finding is noise for the risk register (it still lives in the findings/issues views).
var candidateSeverityRank = map[types.Severity]int{
	types.SeverityCritical: 5,
	types.SeverityHigh:     4,
	types.SeverityMedium:   3,
	types.SeverityLow:      2,
	types.SeverityInfo:     1,
}

// CandidateRisks clusters the tenant's at-or-above-high findings into proposed risk-register entries.
// now is injected for deterministic tests.
func CandidateRisks(tenantID string, findings []types.Finding, now time.Time) []platform.Risk {
	groups := map[string][]types.Finding{}
	for _, f := range findings {
		if candidateSeverityRank[f.Severity] < 4 { // high+ only
			continue
		}
		cat := categorize(f)
		groups[cat] = append(groups[cat], f)
	}

	cats := make([]string, 0, len(groups))
	for c := range groups {
		cats = append(cats, c)
	}
	sort.Strings(cats) // deterministic output order

	out := make([]platform.Risk, 0, len(cats))
	for _, cat := range cats {
		fs := groups[cat]
		ids := make([]string, 0, len(fs))
		maxRank := 0
		for _, f := range fs {
			ids = append(ids, f.ID)
			if r := candidateSeverityRank[f.Severity]; r > maxRank {
				maxRank = r
			}
		}
		sort.Strings(ids)
		out = append(out, platform.Risk{
			ID:          "risk-" + slug(cat),
			TenantID:    tenantID,
			Title:       cat + " exposure",
			Description: describe(cat, len(fs)),
			Category:    cat,
			Impact:      maxRank,                      // worst severity in the cluster drives impact
			Likelihood:  likelihoodFromCount(len(fs)), // more occurrences ⇒ more likely to be hit
			Status:      platform.RiskOpen,
			Proposed:    true, // awaiting a human treatment decision
			FindingIDs:  ids,
			CreatedAt:   now,
		})
	}
	return out
}

// likelihoodFromCount maps how many findings cluster into a category to a starting likelihood (1–5).
// This is an evidence-grounded *starting point* the human owner refines, never a final verdict.
func likelihoodFromCount(n int) int {
	switch {
	case n >= 7:
		return 5
	case n >= 4:
		return 4
	case n >= 2:
		return 3
	default:
		return 2
	}
}

func describe(cat string, n int) string {
	noun := "finding"
	if n != 1 {
		noun += "s"
	}
	return "Proposed from " + itoa(n) + " " + noun + " in the " + strings.ToLower(cat) +
		" category. Set the final likelihood, impact, and treatment with an accountable owner."
}

// categorize buckets a finding into a coarse risk category from its CWE (preferred) or tool. The map
// is intentionally small and coarse — the register groups risk themes, not individual findings.
func categorize(f types.Finding) string {
	for _, c := range f.CWE {
		if cat, ok := cweCategory[normalizeCWE(c)]; ok {
			return cat
		}
	}
	if cat, ok := toolCategory[strings.ToLower(f.Tool)]; ok {
		return cat
	}
	return "Other security"
}

var cweCategory = map[string]string{
	"CWE-89": "Injection", "CWE-79": "Injection", "CWE-78": "Injection", "CWE-94": "Injection",
	"CWE-284": "Access control", "CWE-285": "Access control", "CWE-862": "Access control",
	"CWE-863": "Access control", "CWE-639": "Access control", "CWE-287": "Access control",
	"CWE-1104": "Vulnerable dependencies", "CWE-1395": "Vulnerable dependencies", "CWE-937": "Vulnerable dependencies",
	"CWE-200": "Data exposure", "CWE-359": "Data exposure", "CWE-532": "Data exposure",
	"CWE-327": "Cryptography", "CWE-326": "Cryptography", "CWE-295": "Cryptography",
	"CWE-798": "Secrets management", "CWE-259": "Secrets management",
	"CWE-16": "Misconfiguration", "CWE-693": "Misconfiguration", "CWE-2": "Misconfiguration",
}

var toolCategory = map[string]string{
	"gitleaks": "Secrets management", "trufflehog": "Secrets management",
	"trivy": "Vulnerable dependencies", "grype": "Vulnerable dependencies", "osvscanner": "Vulnerable dependencies",
	"prowler": "Cloud misconfiguration", "scoutsuite": "Cloud misconfiguration", "checkov": "Cloud misconfiguration",
	"semgrep": "Insecure code", "sqlmap": "Injection", "dalfox": "Injection",
	// Non-CWE finding sources — the founder ICP's primary surfaces. Without these they all fall to the
	// vague "Other security" bucket, so a vCISO seeding risk from identity/SaaS threats gets one
	// meaningless "Other security exposure" instead of a real, actionable category.
	"identitythreat": "Identity & access", "operate": "Identity & access", "okta": "Identity & access",
	"sspm": "SaaS configuration",
}

func normalizeCWE(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	if !strings.HasPrefix(c, "CWE-") && c != "" {
		c = "CWE-" + strings.TrimPrefix(c, "CWE")
	}
	return c
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		d = append([]byte{'-'}, d...)
	}
	return string(d)
}

// RegisterSummary is the at-a-glance view of a risk register (the board/owner report).
type RegisterSummary struct {
	Total     int            `json:"total"`
	Open      int            `json:"open"`     // identified, no human decision yet (incl. proposed)
	Accepted  int            `json:"accepted"` // a named human accepted the residual risk
	Treating  int            `json:"treating"` // mitigation/transfer/avoidance in progress
	Closed    int            `json:"closed"`   //
	Proposed  int            `json:"proposed"` // agent-seeded, awaiting triage
	ByLevel   map[string]int `json:"by_level"` // low/medium/high/critical
	TopRiskID string         `json:"top_risk_id,omitempty"`
}

// Summarize tallies a register for the owner/board view. Pure compute, grounded in the stored risks.
func Summarize(risks []platform.Risk) RegisterSummary {
	s := RegisterSummary{ByLevel: map[string]int{}}
	topScore := -1
	for _, r := range risks {
		s.Total++
		s.ByLevel[r.Level()]++
		if r.Proposed {
			s.Proposed++
		}
		switch r.Status {
		case platform.RiskAccepted:
			s.Accepted++
		case platform.RiskTreating:
			s.Treating++
		case platform.RiskClosed:
			s.Closed++
		default:
			s.Open++
		}
		if sc := r.Score(); sc > topScore && r.Status != platform.RiskClosed {
			topScore = sc
			s.TopRiskID = r.ID
		}
	}
	return s
}
