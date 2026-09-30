package crossdetect

import (
	"fmt"
	"math"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// priority.go ranks the issue list the way exposure management ranks, not the way vulnerability
// management does: by EVIDENCE that an attack works, not by severity alone.
//
// # The policy change, stated because it reverses the one before it
//
// The previous tiebreaker kept every boost under the 100-point gap between severities, so evidence
// could only reorder issues INSIDE a band — "never inflate a lesser issue past a worse one". That left
// the product's own differentiator out of its own ranking: a High we EXPLOITED on the customer's live
// system, on CISA's KEV list, sat below an unproven Critical no tool could reach. Gartner's definition
// of an exposure-assessment platform is precisely prioritisation "by threat landscape, business and
// existing security control context" rather than by CVSS; a founder with an afternoon to spend should
// spend it on the proven, actively exploited High. So evidence now moves an issue ACROSS bands — and
// because that is a stronger claim, every point is a named factor with a reason the reader can check.
//
// # Why three axes, and max within each
//
// Several feeds often report the SAME fact: KEV, SSVC "active" and a public exploit all say "attackers
// use this". Adding them would let one fact, seen through three feeds, outrank a fact seen through
// one — so each axis takes its STRONGEST signal only, and only genuinely different facts add up:
//
//   - proven on YOUR system  (attacked in production / exploited by us / provider-confirmed /
//     reachable from your code / corroborated)
//   - exploited in the WILD  (KEV + ransomware / KEV / SSVC active / public exploit / EPSS)
//   - exposure               (a step on an attack path to a crown jewel; reachable from the internet)
//
// A compensating control (a WAF observed blocking this exact attack) LOWERS the rank, never the
// severity: the code is still vulnerable, which is why the issue stays on the list and its reason says
// so. Grounded throughout (§10): no factor is added without the signal that justifies it.

// RankFactor is one named contribution to an issue's RiskRank.
type RankFactor struct {
	Factor string `json:"factor"`
	Points int    `json:"points"`
	Why    string `json:"why"`
}

// Points on each axis. Chosen so proof on the customer's system plus in-the-wild exploitation lifts a
// High above an unproven Critical at the same data tier (300 + 130 + 100 > 400), while evidenceCeiling
// keeps a Low below one (100 + 280 < 400) — evidence reorders what to fix first; it does not turn a Low
// into the most urgent thing on the list.
const (
	ptsAttacked     = 150
	ptsExploited    = 130
	ptsProviderOK   = 60
	ptsReachable    = 50
	ptsCorroborated = 20

	ptsKEVRansomware = 120
	ptsKEV           = 100
	ptsSSVCActive    = 80
	ptsPublicExploit = 40
	ptsEPSSMax       = 80

	ptsAutomatable  = 15
	ptsAttackPath   = 50
	ptsExposed      = 30
	ptsWAFShielded  = -60
	evidenceCeiling = 280 // the most the evidence axes together may add — keeps a Low below any Critical
)

// rungStrength orders the evidence ladder (higher is stronger); unknown is 0.
func rungStrength(r types.EvidenceRung) int {
	all := types.AllEvidenceRungs()
	for i, x := range all {
		if x == r {
			return len(all) - i
		}
	}
	return 0
}

// RankIssue returns the issue's RiskRank and the factors that sum to it.
func RankIssue(i Issue, tier int) (int, []RankFactor) {
	sev := types.Severity(i.Severity)
	base := severityBase(sev)
	factors := []RankFactor{{Factor: "severity", Points: base, Why: string(sev) + " severity"}}
	if d := RiskWeight(sev, tier) - base; d != 0 {
		why := "on an asset holding customer data"
		if d < 0 {
			why = "on a low-sensitivity asset"
		}
		factors = append(factors, RankFactor{Factor: "data_tier", Points: d, Why: why})
	}

	var evidence []RankFactor
	// Axis A — proven on YOUR system (strongest only).
	rung := types.EvidenceRung(i.EvidenceRung)
	switch {
	case i.Attacked:
		evidence = append(evidence, RankFactor{"attacked", ptsAttacked, "seen under attack in your production traffic"})
	case rung.ClaimsExploitability():
		evidence = append(evidence, RankFactor{"exploited", ptsExploited, "we exploited it on your live system"})
	case rung == types.RungProviderConfirmed:
		evidence = append(evidence, RankFactor{"provider_confirmed", ptsProviderOK, "your cloud provider's policy evaluator allowed every step"})
	case rung == types.RungReachabilityConfirmed:
		evidence = append(evidence, RankFactor{"reachable", ptsReachable, "your code reaches the vulnerable function"})
	case i.Confirmed || rung == types.RungCorroborated:
		evidence = append(evidence, RankFactor{"corroborated", ptsCorroborated, "two independent tools agree"})
	}
	// Axis B — exploited in the WILD (strongest only).
	epssPts := int(math.Round(i.EPSS * ptsEPSSMax))
	switch {
	case i.KEV && i.Ransomware:
		evidence = append(evidence, RankFactor{"kev_ransomware", ptsKEVRansomware, "CISA: exploited in the wild, including by ransomware crews"})
	case i.KEV:
		evidence = append(evidence, RankFactor{"kev", ptsKEV, "on CISA's Known Exploited Vulnerabilities list"})
	case i.SSVCActive:
		evidence = append(evidence, RankFactor{"ssvc_active", ptsSSVCActive, "CISA assesses exploitation as active"})
	case i.PublicExploit && ptsPublicExploit >= epssPts:
		evidence = append(evidence, RankFactor{"public_exploit", ptsPublicExploit, "a public exploit exists"})
	case epssPts > 0:
		evidence = append(evidence, RankFactor{"epss", epssPts, fmt.Sprintf("EPSS: %.0f%% chance of exploitation in the next 30 days", i.EPSS*100)})
	}
	if i.SSVCAutomatable {
		evidence = append(evidence, RankFactor{"automatable", ptsAutomatable, "CISA: attackers can automate it across many targets"})
	}
	// Axis C — exposure (different facts, so they add).
	if i.InAttackPath {
		evidence = append(evidence, RankFactor{"attack_path", ptsAttackPath, "a step in an attack path to a crown jewel"})
	}
	if i.Exposed {
		evidence = append(evidence, RankFactor{"internet_exposed", ptsExposed, "reachable from the internet"})
	}

	// Cap the evidence contribution so no amount of it lifts a Low above an unproven Critical. Stated
	// as its own factor when it bites, so the sum on the page still adds up.
	sum := 0
	for _, f := range evidence {
		sum += f.Points
	}
	factors = append(factors, evidence...)
	if sum > evidenceCeiling {
		factors = append(factors, RankFactor{"evidence_cap", evidenceCeiling - sum, "evidence is capped so it never outweighs severity entirely"})
	}

	if i.WAFShielded {
		factors = append(factors, RankFactor{"waf_shielded", ptsWAFShielded, "a WAF blocked this attack in testing — a mitigation, not a fix"})
	}

	total := 0
	for _, f := range factors {
		total += f.Points
	}
	if total < 1 {
		total = 1 // an issue on the list is never ranked as nothing
	}
	return total, factors
}
