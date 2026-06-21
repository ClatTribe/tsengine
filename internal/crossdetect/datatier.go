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
// DataTier + the resulting RiskRank (severity × tier), and re-sorts the list so the
// highest-risk issues lead — the Synthesia "tier repos by customer-data exposure → its findings
// jump the queue" behavior. With every asset at the default Standard tier the ranking reduces
// to severity-first (today's order), so this is a no-op until an owner tiers an asset.
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
		issues[i].RiskRank = RiskWeight(types.Severity(issues[i].Severity), tier)
	}
	sort.SliceStable(issues, func(a, b int) bool { return issues[a].RiskRank > issues[b].RiskRank })
	return issues
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
