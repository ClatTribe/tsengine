package bench

import (
	"fmt"
	"sort"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// impact.go is the IMPACT-ACCURACY dimension of the AI Security Engineer benchmark — the OTHER half of the
// engineer's job. `defensexbow` asks "did the estate get verifiably safer" (remediation). This asks: "did
// the engineer correctly tell the org what MATTERS and why" — the contextual impact judgment a scanner
// cannot do and the differentiated AI value.
//
// The design keeps the §2.7 / §13 line honest: the DETERMINISTIC substrate computes the impact FACTS
// (reachability, crown-jewel reach via crossdetect attack paths, data-tier via RiskWeight); this scores
// whether the engineer's assessment (a) AGREES with those facts, (b) PRIORITIZES by real impact rather than
// raw severity, and (c) INVENTS no impact the facts don't support (§10). We do NOT ask the LLM to recompute
// what the substrate already computes — we measure its judgment ON TOP of the grounded facts.
//
// The load-bearing insight the engineer must get right: RAW SEVERITY != ORGANISATIONAL IMPACT. A Medium
// that reaches a customer-PII crown jewel outranks a Critical on a throwaway dev box. That reprioritization
// is exactly what a human security engineer does and what this measures.

// ImpactIssue is one finding to assess, carrying its ground-truth impact facts (from the substrate).
type ImpactIssue struct {
	ID           string         `json:"id"`
	Title        string         `json:"title,omitempty"`
	Severity     types.Severity `json:"severity"`
	DataTier     int            `json:"data_tier"`     // 1=customer-data … 3=low (platform.DataTier)
	ReachesCrown bool           `json:"reaches_crown"` // ground truth: reaches a crown jewel (crossdetect path)
}

// groundScore is the deterministic ground-truth impact: the substrate's data-tier-adjusted RiskWeight,
// boosted when the finding actually reaches a crown jewel (a reachable path to sensitive data / admin is
// what makes a finding matter beyond its raw severity). This is the answer key — computed, not authored.
func groundScore(i ImpactIssue) int {
	w := crossdetect.RiskWeight(i.Severity, i.DataTier)
	if i.ReachesCrown {
		w *= 2 // reaching a crown jewel doubles the real impact
	}
	return w
}

// ImpactScenario is a seeded estate with ground-truth impact per issue.
type ImpactScenario struct {
	ID     string        `json:"id"`
	Name   string        `json:"name,omitempty"`
	Issues []ImpactIssue `json:"issues"`
}

// EngineerAssessment is what the AI engineer produced: a prioritization + per-issue crown-jewel claims.
type EngineerAssessment struct {
	RankedIssueIDs   []string        `json:"ranked_issue_ids"`   // most-important first
	CrownJewelClaims map[string]bool `json:"crown_jewel_claims"` // per-issue: does it reach a crown jewel
}

// ImpactScore grades the assessment against the ground truth.
type ImpactScore struct {
	ScenarioID string `json:"scenario_id"`

	// Crown-jewel identification — did it find what truly reaches a crown jewel, and invent nothing.
	CrownTP  int      `json:"crown_tp"`
	Invented []string `json:"invented,omitempty"` // claimed crown reach with NO grounding — hallucinated impact (§10)
	Missed   []string `json:"missed,omitempty"`   // real crown reaches it failed to flag

	// Prioritization — do the org's real top-impact issues lead the engineer's ranking.
	K           int     `json:"k"`            // the count of genuinely high-impact issues (the ones that must lead)
	TopKHit     int     `json:"topk_hit"`     // how many of them the engineer put in its own top-K
	RankQuality float64 `json:"rank_quality"` // TopKHit / K  (1.0 == the right issues lead)
}

// Pass is the clean bar: the real top-impact issues all lead, every crown reach is identified, and nothing
// is invented (the grounding gate). A partial run is reported by the numbers, not hidden.
func (s ImpactScore) Pass() bool {
	return s.RankQuality >= 1.0 && len(s.Missed) == 0 && len(s.Invented) == 0
}

// ScoreImpact grades an engineer's assessment. Pure + deterministic — the ground truth is computed from the
// substrate's RiskWeight + the seeded crown-jewel facts, so it never depends on the LLM to be its own oracle.
func ScoreImpact(sc ImpactScenario, a EngineerAssessment) ImpactScore {
	s := ImpactScore{ScenarioID: sc.ID}

	// Crown-jewel scoring: compare the engineer's claims against the ground-truth facts.
	truth := map[string]bool{}
	for _, is := range sc.Issues {
		truth[is.ID] = is.ReachesCrown
	}
	for id, claimed := range a.CrownJewelClaims {
		if !claimed {
			continue
		}
		if t, ok := truth[id]; ok && t {
			s.CrownTP++
		} else {
			s.Invented = append(s.Invented, id) // claimed a crown reach the facts don't support (or unknown id)
		}
	}
	for _, is := range sc.Issues {
		if is.ReachesCrown && !a.CrownJewelClaims[is.ID] {
			s.Missed = append(s.Missed, is.ID)
		}
	}
	sort.Strings(s.Invented)
	sort.Strings(s.Missed)

	// Prioritization: the ground-truth top-K are the K genuinely high-impact issues (those that reach a
	// crown jewel; if none do, fall back to the top-scoring third). The engineer's own top-K must contain
	// them — this rewards prioritising by REAL impact, not raw severity.
	ranked := append([]ImpactIssue(nil), sc.Issues...)
	sort.SliceStable(ranked, func(i, j int) bool { return groundScore(ranked[i]) > groundScore(ranked[j]) })
	crownSet := map[string]bool{}
	for _, is := range sc.Issues {
		if is.ReachesCrown {
			crownSet[is.ID] = true
		}
	}
	k := len(crownSet)
	if k == 0 { // no crown reaches → the top third by ground score are "what matters"
		k = (len(ranked) + 2) / 3
		crownSet = map[string]bool{}
		for i := 0; i < k && i < len(ranked); i++ {
			crownSet[ranked[i].ID] = true
		}
	}
	s.K = k
	engTopK := map[string]bool{}
	for i := 0; i < k && i < len(a.RankedIssueIDs); i++ {
		engTopK[a.RankedIssueIDs[i]] = true
	}
	for id := range crownSet {
		if engTopK[id] {
			s.TopKHit++
		}
	}
	if s.K > 0 {
		s.RankQuality = float64(s.TopKHit) / float64(s.K)
	} else {
		s.RankQuality = 1.0
	}
	return s
}

// RenderImpactScore is a one-line human summary.
func RenderImpactScore(s ImpactScore) string {
	pass := ""
	if s.Pass() {
		pass = " [PASS]"
	}
	return fmt.Sprintf("%s: crown %d/%d correct (missed %d, invented %d) · priority %d/%d lead (%.0f%%)%s",
		s.ScenarioID, s.CrownTP, s.CrownTP+len(s.Missed), len(s.Missed), len(s.Invented),
		s.TopKHit, s.K, s.RankQuality*100, pass)
}
