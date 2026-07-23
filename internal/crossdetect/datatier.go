package crossdetect

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// severityBase ranks a severity for risk-weighting. This mirrors the engine's severity
// ordering but lives in the platform layer — the engine's own surface_priority is never
// touched (§18.2 invariant 1). Values are spaced so adjacent severities don't collide after
// the tier multiplier below.
func severityBase(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 400
	case types.SeverityHigh:
		return 300
	case types.SeverityMedium:
		return 200
	case types.SeverityLow:
		return 100
	default: // info / unknown
		return 50
	}
}

// RiskWeight is the data-tier-adjusted priority of a finding at the given severity on an asset
// of the given data tier (the Synthesia "tier repos by customer-data exposure → prioritize
// their findings" idea). Tier 1 (customer data) raises the weight by 50%, tier 3 lowers it by
// 40%. Severity stays the dominant term WITHIN a tier (critical > high > medium > low > info),
// but the tier lets a Medium on a customer-data repo (300) outrank a Medium on a
// low-sensitivity one (120) and edge a Low on a standard repo (100) — exactly the cross-repo
// reprioritization tiering is for. An unknown/out-of-range tier is treated as Standard.
func RiskWeight(sev types.Severity, tier int) int {
	base := severityBase(sev)
	switch tier {
	case platform.DataTierCritical:
		return base * 3 / 2 // +50%
	case platform.DataTierLow:
		return base * 3 / 5 // -40%
	default:
		return base
	}
}

// PrioritizeByDataTier attributes each issue to a tiered asset, annotates it with that asset's
// DataTier + the resulting RiskRank (severity × tier + an exploitability tiebreaker), and re-sorts
// the list so the highest-risk issues lead — the Synthesia "tier repos by customer-data exposure →
// its findings jump the queue" behavior, plus the Wiz/Synthesia "prioritize by real
// exploitability" lens. With every asset at the default Standard tier the ranking reduces to
// severity-first, then attacked-first, then confirmed-first within a severity (the exploitability
// tiebreaker is the only re-ordering until an owner tiers an asset).
//
// Attribution is BEST-EFFORT and grounded (§10 — never guessed): an issue maps to an asset only
// when that asset's non-empty Target literally appears in the issue's Endpoint (the longest
// such Target wins). This reliably tiers URL-bearing issues (web/api); issues whose endpoint
// can't be tied to a tiered asset (e.g. a repo finding's file:line) stay at Standard — honest,
// never a fabricated attribution. A proper finding→asset link in the data model is the follow-up.
func PrioritizeByDataTier(issues []Issue, assets []platform.Asset) []Issue {
	for i := range issues {
		tier := tierForEndpoint(issues[i].Endpoint, assets)
		issues[i].DataTier = tier
		issues[i].RiskRank = RiskWeight(types.Severity(issues[i].Severity), tier) + exploitabilityBoost(issues[i]) + ssvcBoost(issues[i])
	}
	sort.SliceStable(issues, func(a, b int) bool { return issues[a].RiskRank > issues[b].RiskRank })
	return issues
}

// exploitabilityBoost is the within-severity tiebreaker for how PROVEN an issue is — the
// "prioritize by real exploitability" lens (Wiz/Synthesia). Additive + modest (< the 100-point
// severity gap), so it orders issues inside a severity band without inflating a lesser issue past
// a worse one: an Attacked issue (observed exploited in the wild — the strongest fix-first signal)
// leads a Confirmed one (≥2 independent tools agree → more likely a true positive), which leads an
// unproven one. Attacked supersedes Confirmed (it's the stronger evidence), so they don't stack.
func exploitabilityBoost(i Issue) int {
	switch {
	case i.Live: // genuinely live-exploitable (ACSP fusion) — the strongest fix-first signal
		return 80
	case i.Attacked:
		return 60
	case i.Confirmed:
		return 20
	}
	return 0
}

// ssvcBoost is the threat-intel-urgency term (a DIFFERENT axis from exploitabilityBoost's proof-of-exploit):
// a CISA SSVC "act" decision (actively exploited + high impact — patch now) leads, "attend" (out-of-cycle)
// next. Small + additive, and capped so exploitabilityBoost(≤80) + ssvcBoost(≤15) stays under the 100-point
// severity gap — it re-orders WITHIN a severity band, never lifts a lesser issue past a worse one.
func ssvcBoost(i Issue) int {
	switch i.SSVC {
	case "act":
		return 15
	case "attend":
		return 8
	}
	return 0
}

// tierForEndpoint returns the data tier of the asset whose Target best matches the endpoint,
// or Standard when none does. Longest matching Target wins (so a specific path-asset beats a
// broad host-asset).
func tierForEndpoint(endpoint string, assets []platform.Asset) int {
	if endpoint == "" {
		return platform.DataTierStandard
	}
	best, bestLen := platform.DataTierStandard, 0
	for _, a := range assets {
		if a.Target == "" || len(a.Target) <= bestLen {
			continue
		}
		if strings.Contains(endpoint, a.Target) {
			best, bestLen = a.DataTier(), len(a.Target)
		}
	}
	return best
}
