package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// impactScenario: the load-bearing case — raw severity != org impact.
//   - crit-dev:   CRITICAL on a tier-3 throwaway dev box, reaches nothing  (score 240)
//   - high-app:   HIGH on a standard app, reaches nothing                  (score 300)
//   - med-pii:    MEDIUM on a tier-1 customer-data asset, REACHES a crown  (score 600)  <- what truly matters
//
// A good engineer ranks med-pii first; a severity-naive one ranks crit-dev first and fails.
func impactScenario() ImpactScenario {
	return ImpactScenario{
		ID: "impact-priority", Issues: []ImpactIssue{
			{ID: "crit-dev", Severity: types.SeverityCritical, DataTier: 3, ReachesCrown: false},
			{ID: "high-app", Severity: types.SeverityHigh, DataTier: 2, ReachesCrown: false},
			{ID: "med-pii", Severity: types.SeverityMedium, DataTier: 1, ReachesCrown: true},
		},
	}
}

// TestScoreImpact_RewardsRealImpactOverSeverity: the engineer that prioritises by ACTUAL impact (the
// crown-reaching customer-data medium) and correctly identifies the crown reach PASSES.
func TestScoreImpact_RewardsRealImpactOverSeverity(t *testing.T) {
	sc := impactScenario()
	good := EngineerAssessment{
		RankedIssueIDs:   []string{"med-pii", "high-app", "crit-dev"},
		CrownJewelClaims: map[string]bool{"med-pii": true},
	}
	s := ScoreImpact(sc, good)
	if s.K != 1 || s.TopKHit != 1 || s.RankQuality != 1.0 {
		t.Errorf("the crown-reaching issue must lead: k=%d hit=%d q=%.2f", s.K, s.TopKHit, s.RankQuality)
	}
	if s.CrownTP != 1 || len(s.Invented) != 0 || len(s.Missed) != 0 {
		t.Errorf("crown identification should be perfect: %s", RenderImpactScore(s))
	}
	if !s.Pass() {
		t.Errorf("a correct impact assessment must PASS: %s", RenderImpactScore(s))
	}
}

// TestScoreImpact_PenalisesSeverityFirst: an engineer that ranks by RAW SEVERITY (critical-on-a-dev-box
// first) mis-prioritises — the benchmark must NOT pass it. This is the whole point: impact != severity.
func TestScoreImpact_PenalisesSeverityFirst(t *testing.T) {
	sc := impactScenario()
	naive := EngineerAssessment{
		RankedIssueIDs:   []string{"crit-dev", "high-app", "med-pii"}, // severity-first
		CrownJewelClaims: map[string]bool{"med-pii": true},            // it got the fact right, but ranked wrong
	}
	s := ScoreImpact(sc, naive)
	if s.RankQuality != 0.0 {
		t.Errorf("severity-first ranking must miss the real top issue: q=%.2f (%s)", s.RankQuality, RenderImpactScore(s))
	}
	if s.Pass() {
		t.Error("a severity-first assessment must NOT pass — impact != severity")
	}
}

// TestScoreImpact_GroundingGuards: hallucinated impact (a crown reach the facts don't support) and a missed
// real crown reach both block a pass — the §10 anti-hallucination bar applied to impact.
func TestScoreImpact_GroundingGuards(t *testing.T) {
	sc := impactScenario()

	// Invents a crown reach on the dev box (false) → hallucinated impact.
	halluc := EngineerAssessment{
		RankedIssueIDs:   []string{"med-pii", "high-app", "crit-dev"},
		CrownJewelClaims: map[string]bool{"med-pii": true, "crit-dev": true},
	}
	if s := ScoreImpact(sc, halluc); len(s.Invented) != 1 || s.Invented[0] != "crit-dev" || s.Pass() {
		t.Errorf("invented crown reach must be flagged + block pass: %s", RenderImpactScore(s))
	}

	// Misses the real crown reach → under-assessed impact.
	missed := EngineerAssessment{
		RankedIssueIDs:   []string{"med-pii", "high-app", "crit-dev"},
		CrownJewelClaims: map[string]bool{},
	}
	if s := ScoreImpact(sc, missed); len(s.Missed) != 1 || s.Missed[0] != "med-pii" || s.Pass() {
		t.Errorf("missed crown reach must be flagged + block pass: %s", RenderImpactScore(s))
	}
}

// TestScoreImpact_MisTagged_AIValueAdd: the deterministic substrate ranking (tags only) FAILS on a
// mis-tagged finding, but an engineer that READS the detail and overrides the tag PASSES. The gap between
// them IS the AI Security Engineer's measured value-add — the thing a deterministic RiskWeight cannot do.
func TestScoreImpact_MisTagged_AIValueAdd(t *testing.T) {
	sc := ImpactScenario{ID: "mis-tagged", Issues: []ImpactIssue{
		// Tagged tier-3 / medium (low naive score), but the DETAIL reveals a prod admin key -> true impact huge.
		{ID: "admin-key", Severity: types.SeverityMedium, DataTier: 3, ReachesCrown: false,
			Detail: "leaked key is an AWS root/admin access key with AdministratorAccess", TrueImpact: 1000},
		{ID: "crit-devbox", Severity: types.SeverityCritical, DataTier: 3, ReachesCrown: false},
		{ID: "high-app", Severity: types.SeverityHigh, DataTier: 2, ReachesCrown: false},
	}}
	// Substrate-only baseline ranks by the tags (high-app > crit-devbox > admin-key) -> puts admin-key last.
	if naive := ScoreImpact(sc, NaiveBaseline(sc)); naive.Pass() {
		t.Errorf("the substrate-only baseline must FAIL the mis-tagged scenario (it can't read the detail): %s",
			RenderImpactScore(naive))
	}
	// The engineer that reads the detail overrides the tag and leads with admin-key -> passes.
	good := EngineerAssessment{RankedIssueIDs: []string{"admin-key", "high-app", "crit-devbox"}, CrownJewelClaims: map[string]bool{}}
	if g := ScoreImpact(sc, good); !g.Pass() {
		t.Errorf("an engineer that reads the detail + overrides the tag must PASS: %s", RenderImpactScore(g))
	}
}
