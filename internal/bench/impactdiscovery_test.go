package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// discoveryScenario: a noisy estate. Two findings create REAL impact (a cross-surface chain + a public PII
// bucket); the rest are noise (a critical RCE on a throwaway box, a medium on a marketing site).
func discoveryScenario() DiscoveryScenario {
	return DiscoveryScenario{ID: "estate", Findings: []DiscoveryFinding{
		{ID: "leaked-key", Surface: "code", Severity: types.SeverityMedium, HighImpact: true, ImpactType: ImpactLateral,
			Reaches: "PII bucket via cloud role", Detail: "AWS key in repo → assumable deploy role → customer-PII S3"},
		{ID: "public-pii", Surface: "cloud", Severity: types.SeverityHigh, HighImpact: true, ImpactType: ImpactDataExposure,
			Reaches: "customer PII", Detail: "S3 bucket with customer records is public"},
		{ID: "rce-devbox", Surface: "cloud", Severity: types.SeverityCritical, HighImpact: false,
			Detail: "RCE on an isolated throwaway CI box, no creds, torn down nightly"},
		{ID: "xss-marketing", Surface: "web", Severity: types.SeverityMedium, HighImpact: false,
			Detail: "reflected XSS on the public marketing microsite, no data"},
	}}
}

// TestScoreDiscovery_PerfectFindsImpactfulNotNoise: surfacing exactly the two impactful findings PASSES.
func TestScoreDiscovery_PerfectFindsImpactfulNotNoise(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii"}}
	s := ScoreDiscovery(sc, d)
	if s.Recall != 1.0 || s.FP != 0 || s.FN != 0 || len(s.Invented) != 0 {
		t.Fatalf("perfect discovery: %s", RenderDiscoveryScore(s))
	}
	if !s.Pass() {
		t.Errorf("finding exactly the impactful findings must PASS: %s", RenderDiscoveryScore(s))
	}
	// per-category recall recorded.
	if s.ByType[ImpactLateral].Found != 1 || s.ByType[ImpactDataExposure].Found != 1 {
		t.Errorf("by-type recall wrong: %+v", s.ByType)
	}
}

// TestScoreDiscovery_MissingTheChainFails: missing the cross-surface chain (the hardest, highest-value
// find) drops recall below 1 — the worst failure for "find the vuln that creates real impact".
func TestScoreDiscovery_MissingTheChainFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"public-pii"}} // missed the leaked-key chain
	s := ScoreDiscovery(sc, d)
	if s.Recall >= 1.0 || len(s.Missed) != 1 || s.Missed[0] != "leaked-key" {
		t.Errorf("missing the chain must lower recall + flag it: %s", RenderDiscoveryScore(s))
	}
	if s.Pass() {
		t.Error("missing a real-impact finding must NOT pass")
	}
}

// TestScoreDiscovery_FlagEverythingFails: the gaming guard — flagging ALL findings as high-impact reaches
// recall 1 but generates false alarms (FP>0), so it must NOT pass. "Cry wolf on everything" is not discovery.
func TestScoreDiscovery_FlagEverythingFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii", "rce-devbox", "xss-marketing"}}
	s := ScoreDiscovery(sc, d)
	if s.Recall != 1.0 {
		t.Errorf("flag-everything trivially has recall 1, got %.2f", s.Recall)
	}
	if s.FP != 2 {
		t.Errorf("the two noise findings flagged high must be false alarms, got FP=%d", s.FP)
	}
	if s.Pass() {
		t.Error("flag-everything must NOT pass — precision guards against crying wolf")
	}
}

// TestScoreDiscovery_InventedFails: claiming a finding not in the estate is a hallucination (§10).
func TestScoreDiscovery_InventedFails(t *testing.T) {
	sc := discoveryScenario()
	d := EngineerDiscovery{HighImpactIDs: []string{"leaked-key", "public-pii", "ghost"}}
	s := ScoreDiscovery(sc, d)
	if len(s.Invented) != 1 || s.Invented[0] != "ghost" || s.Pass() {
		t.Errorf("an invented finding must be flagged + block pass: %s", RenderDiscoveryScore(s))
	}
}
