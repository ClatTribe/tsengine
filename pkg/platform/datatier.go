package platform

import "strconv"

// Data-sensitivity tiers for an asset (the Synthesia "tier repos by customer-data exposure"
// pattern). A Tier-1 asset handles customer / regulated data, so its findings are prioritized
// over the same finding on a low-sensitivity asset — the platform's risk-adjusted ranking
// (crossdetect.RiskWeight) multiplies severity by the tier. This is platform metadata only:
// the engine's surface_priority is untouched (§18.2 invariant 1).
const (
	DataTierCritical = 1 // handles customer / regulated data — prioritize its findings
	DataTierStandard = 2 // default — internal app, no special sensitivity
	DataTierLow      = 3 // low-sensitivity / throwaway — deprioritize
	DataTierDefault  = DataTierStandard
)

// dataTierMetaKey is where the tier lives on Asset.Meta — chosen over a typed struct field so
// no store-serialization / conformance-suite change ripples out (Meta already round-trips).
const dataTierMetaKey = "data_tier"

// DataTier returns the asset's customer-data-sensitivity tier, defaulting to Standard when
// unset or unparseable (never guess a higher tier than was set).
func (a Asset) DataTier() int {
	if a.Meta == nil {
		return DataTierDefault
	}
	switch a.Meta[dataTierMetaKey] {
	case "1":
		return DataTierCritical
	case "3":
		return DataTierLow
	default:
		return DataTierStandard
	}
}

// WithDataTier returns a copy of the asset with its data tier set (Meta cloned, not mutated in
// place, so a stored reference isn't aliased).
func (a Asset) WithDataTier(tier int) Asset {
	m := make(map[string]string, len(a.Meta)+1)
	for k, v := range a.Meta {
		m[k] = v
	}
	m[dataTierMetaKey] = strconv.Itoa(tier)
	a.Meta = m
	return a
}

// ValidDataTier reports whether t is a defined tier (1..3).
func ValidDataTier(t int) bool { return t >= DataTierCritical && t <= DataTierLow }

// DataTierLabel is the human label for a tier.
func DataTierLabel(t int) string {
	switch t {
	case DataTierCritical:
		return "Customer data"
	case DataTierLow:
		return "Low sensitivity"
	default:
		return "Standard"
	}
}
