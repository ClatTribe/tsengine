package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func rank(i Issue) (int, []RankFactor) { return RankIssue(i, platform.DataTierStandard) }

func factor(fs []RankFactor, name string) (RankFactor, bool) {
	for _, f := range fs {
		if f.Factor == name {
			return f, true
		}
	}
	return RankFactor{}, false
}

// The headline: a High we EXPLOITED that is also on KEV outranks an unproven Critical.
func TestRank_ProvenAndKEVHighOutranksUnprovenCritical(t *testing.T) {
	high, _ := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited), KEV: true})
	crit, _ := rank(Issue{Severity: "critical"})
	if high <= crit {
		t.Fatalf("an exploited, KEV-listed high (%d) must outrank an unproven critical (%d)", high, crit)
	}
}

// "verified" means different things; only the RUNG decides. A provider-confirmed cloud path is an
// authorization fact and a config observation is a setting — neither is an exploit.
func TestRank_OnlyTheExploitedRungEarnsTheExploitPoints(t *testing.T) {
	_, fs := rank(Issue{Severity: "high", EvidenceRung: string(types.RungProviderConfirmed)})
	if _, ok := factor(fs, "exploited"); ok {
		t.Fatal("a provider-confirmed path must not be credited as exploited")
	}
	if _, ok := factor(fs, "provider_confirmed"); !ok {
		t.Fatal("a provider-confirmed path earns its own, smaller factor")
	}
	_, fs = rank(Issue{Severity: "high", EvidenceRung: string(types.RungConfigObserved)})
	for _, f := range fs {
		if f.Factor != "severity" {
			t.Fatalf("a config observation is a fact about a setting, not exploitation evidence: got %+v", f)
		}
	}
}

// Several feeds saying the same fact must not stack: KEV + SSVC-active + public exploit + EPSS is ONE
// "exploited in the wild" signal, credited at its strongest.
func TestRank_InTheWildFeedsDoNotDoubleCount(t *testing.T) {
	all, fs := rank(Issue{Severity: "medium", KEV: true, SSVCActive: true, PublicExploit: true, EPSS: 0.97})
	kevOnly, _ := rank(Issue{Severity: "medium", KEV: true})
	if all != kevOnly {
		t.Fatalf("four feeds reporting one fact must score as the strongest one: %d vs KEV alone %d (%+v)", all, kevOnly, fs)
	}
}

// Genuinely different facts DO add: proven on your system + exploited in the wild + on an attack path.
func TestRank_IndependentFactsAdd(t *testing.T) {
	a, _ := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited)})
	b, _ := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited), KEV: true})
	c, _ := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited), KEV: true, InAttackPath: true})
	if !(a < b && b < c) {
		t.Fatalf("independent evidence must add: %d < %d < %d", a, b, c)
	}
}

// The order must be checkable: the factors sum to the rank, and every one says why.
func TestRank_FactorsSumToTheRankAndExplainThemselves(t *testing.T) {
	cases := []Issue{
		{Severity: "critical", Attacked: true, KEV: true, Ransomware: true, InAttackPath: true, Exposed: true, SSVCAutomatable: true},
		{Severity: "high", EvidenceRung: string(types.RungExploited), EPSS: 0.4, WAFShielded: true},
		{Severity: "low", Confirmed: true},
		{Severity: "info", WAFShielded: true},
	}
	for _, c := range cases {
		total, fs := rank(c)
		sum := 0
		for _, f := range fs {
			sum += f.Points
			if f.Why == "" || f.Factor == "" {
				t.Fatalf("every factor must name itself and say why: %+v", f)
			}
		}
		if sum < 1 {
			sum = 1
		}
		if sum != total {
			t.Fatalf("factors must sum to the rank: sum %d != rank %d for %+v", sum, total, c)
		}
	}
}

// A WAF blocking the attack lowers the RANK, never the severity — the code is still vulnerable.
func TestRank_WAFShieldedLowersRankNotSeverity(t *testing.T) {
	open, _ := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited)})
	shielded, fs := rank(Issue{Severity: "high", EvidenceRung: string(types.RungExploited), WAFShielded: true})
	if shielded >= open {
		t.Fatalf("a compensating control must lower the rank: %d vs %d", shielded, open)
	}
	f, ok := factor(fs, "waf_shielded")
	if !ok || f.Points >= 0 {
		t.Fatalf("the WAF factor must be named and negative: %+v", fs)
	}
	out := PrioritizeByDataTier([]Issue{{Key: "k", Severity: "high", WAFShielded: true}}, nil)
	if out[0].Severity != "high" {
		t.Fatalf("ranking must never change severity: %q", out[0].Severity)
	}
}

// No factor is invented: an issue with no evidence carries only its severity.
func TestRank_NoSignalNoFactor(t *testing.T) {
	_, fs := rank(Issue{Severity: "medium"})
	if len(fs) != 1 || fs[0].Factor != "severity" {
		t.Fatalf("an issue with no evidence must carry only its severity: %+v", fs)
	}
}

// The issue must carry the strongest rung across its findings, read from the ladder.
func TestUnifiedIssues_AggregatesStrongestRungAndCISASignals(t *testing.T) {
	scanner := types.Finding{ID: "a", RuleID: "r", Endpoint: "https://x/y", Severity: types.SeverityHigh, Tool: "nuclei"}
	exploit := types.Finding{ID: "b", RuleID: "r", Endpoint: "https://x/y", Severity: types.SeverityHigh, Tool: "web-investigate",
		VerificationStatus: types.VerificationVerified, Description: "[Exploitation PoC] ran and held",
		ThreatIntel: &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true, Ransomware: true},
			SSVC: &types.SSVC{Exploitation: "Active", Automatable: "yes"}}}
	issues := UnifiedIssues([]types.Finding{scanner, exploit})
	if len(issues) != 1 {
		t.Fatalf("want one issue, got %d", len(issues))
	}
	got := issues[0]
	// Pinned to the literal rung, not to DeriveRung(): if the fixture ever stopped satisfying the
	// ladder, comparing against the function would pass with both findings on the floor.
	if got.EvidenceRung != string(types.RungExploited) {
		t.Fatalf("want the strongest rung %q across the group, got %q", types.RungExploited, got.EvidenceRung)
	}
	if !got.Ransomware || !got.SSVCActive || !got.SSVCAutomatable {
		t.Fatalf("CISA signals must aggregate onto the issue: %+v", got)
	}
}
