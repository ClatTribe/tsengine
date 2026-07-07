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

	// Detail is the finding's evidence/description — the CONTEXT a security engineer reads to judge true
	// impact (e.g. "the leaked key has AdministratorAccess"). It is what lets the engineer OVERRIDE a
	// misleading tag. Surfaced to the engineer in the prompt.
	Detail string `json:"detail,omitempty"`
	// TrueImpact, when >0, is the AUTHORED ground-truth impact for a MIS-TAGGED finding — where the real
	// impact (justified by Detail) differs from what the naive tag/RiskWeight computes. This is the ONLY
	// place the benchmark isn't purely computed, and it is what measures the AI's value-ADD over the
	// deterministic substrate: a substrate-only ranking uses the naive score and gets these wrong; only an
	// engineer that READS Detail ranks them right. Must be justified by Detail (a fair judgment test, §10).
	TrueImpact int `json:"true_impact,omitempty"`
}

// naiveScore is what the DETERMINISTIC substrate alone computes from the tags: the data-tier-adjusted
// RiskWeight, crown-boosted. This is the baseline the AI must BEAT on mis-tagged findings.
func naiveScore(i ImpactIssue) int {
	w := crossdetect.RiskWeight(i.Severity, i.DataTier)
	if i.ReachesCrown {
		w *= 2 // reaching a crown jewel doubles the real impact
	}
	return w
}

// groundScore is the answer-key impact: the authored TrueImpact when set (mis-tagged findings that require
// judgment), else the computed naiveScore. So a scenario with no overrides scores exactly as before.
func groundScore(i ImpactIssue) int {
	if i.TrueImpact > 0 {
		return i.TrueImpact
	}
	return naiveScore(i)
}

// NaiveBaseline is the assessment a SUBSTRATE-ONLY approach (no LLM reading Detail) would produce: rank by
// naiveScore, and claim crown reach exactly per the tags. Scoring THIS against a mis-tagged scenario shows
// the deterministic layer fails there — the gap ScoreImpact(engineer) - ScoreImpact(NaiveBaseline) is the
// AI engineer's measured value-add.
func NaiveBaseline(sc ImpactScenario) EngineerAssessment {
	ranked := append([]ImpactIssue(nil), sc.Issues...)
	sort.SliceStable(ranked, func(i, j int) bool { return naiveScore(ranked[i]) > naiveScore(ranked[j]) })
	a := EngineerAssessment{CrownJewelClaims: map[string]bool{}}
	for _, is := range ranked {
		a.RankedIssueIDs = append(a.RankedIssueIDs, is.ID)
		a.CrownJewelClaims[is.ID] = is.ReachesCrown
	}
	return a
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
	// K = how many issues "clearly matter" — those reaching a crown jewel OR whose Detail makes them
	// high-impact despite a low tag (TrueImpact override). Including overrides is what makes the test
	// require the engineer to READ the detail, not just trust the tags. If nothing is specially flagged,
	// K is the top third.
	k := 0
	for _, is := range sc.Issues {
		if is.ReachesCrown || is.TrueImpact > 0 {
			k++
		}
	}
	if k == 0 {
		k = (len(ranked) + 2) / 3
	}
	// The must-lead set is ALWAYS the top-K by ground-truth impact (groundScore) — so it can never diverge
	// from the answer-key ranking (a crown-reaching LOW finding outscored by a CRITICAL non-crown must not
	// be "required to lead" over the higher-impact issue; consistency bug guard).
	crownSet := map[string]bool{}
	for i := 0; i < k && i < len(ranked); i++ {
		crownSet[ranked[i].ID] = true
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
