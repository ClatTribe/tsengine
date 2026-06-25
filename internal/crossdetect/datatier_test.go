package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestRiskWeight_TierReprioritizes(t *testing.T) {
	// Severity dominates within a tier.
	for _, tier := range []int{platform.DataTierCritical, platform.DataTierStandard, platform.DataTierLow} {
		if RiskWeight(types.SeverityCritical, tier) <= RiskWeight(types.SeverityHigh, tier) {
			t.Errorf("tier %d: critical must outrank high", tier)
		}
		if RiskWeight(types.SeverityHigh, tier) <= RiskWeight(types.SeverityMedium, tier) {
			t.Errorf("tier %d: high must outrank medium", tier)
		}
	}

	// The whole point of tiering: a Medium on a customer-data repo outranks a Medium on a
	// low-sensitivity repo, and edges a Low on a standard repo.
	medCrit := RiskWeight(types.SeverityMedium, platform.DataTierCritical)
	medLow := RiskWeight(types.SeverityMedium, platform.DataTierLow)
	lowStd := RiskWeight(types.SeverityLow, platform.DataTierStandard)
	if medCrit <= medLow {
		t.Errorf("medium@customer-data (%d) must outrank medium@low-sensitivity (%d)", medCrit, medLow)
	}
	if medCrit <= lowStd {
		t.Errorf("medium@customer-data (%d) must outrank low@standard (%d)", medCrit, lowStd)
	}

	// Tier 1 raises, tier 3 lowers, relative to standard.
	base := RiskWeight(types.SeverityHigh, platform.DataTierStandard)
	if RiskWeight(types.SeverityHigh, platform.DataTierCritical) <= base {
		t.Error("tier 1 must raise the weight")
	}
	if RiskWeight(types.SeverityHigh, platform.DataTierLow) >= base {
		t.Error("tier 3 must lower the weight")
	}

	// An unknown tier degrades to standard, never higher.
	if RiskWeight(types.SeverityHigh, 99) != base {
		t.Error("unknown tier should be treated as standard")
	}
}

func TestAssetDataTier_DefaultAndSet(t *testing.T) {
	var a platform.Asset
	if a.DataTier() != platform.DataTierDefault {
		t.Errorf("unset → default (standard), got %d", a.DataTier())
	}
	a = a.WithDataTier(platform.DataTierCritical)
	if a.DataTier() != platform.DataTierCritical {
		t.Errorf("WithDataTier(1) → 1, got %d", a.DataTier())
	}
	if a.Meta["data_tier"] != "1" {
		t.Errorf("tier persisted in Meta, got %q", a.Meta["data_tier"])
	}
	// WithDataTier clones Meta (doesn't alias the original's map).
	b := a.WithDataTier(platform.DataTierLow)
	if a.DataTier() != platform.DataTierCritical {
		t.Error("WithDataTier must not mutate the receiver's Meta")
	}
	if b.DataTier() != platform.DataTierLow {
		t.Errorf("b should be tier 3, got %d", b.DataTier())
	}
	if !platform.ValidDataTier(1) || !platform.ValidDataTier(3) || platform.ValidDataTier(0) || platform.ValidDataTier(4) {
		t.Error("ValidDataTier bounds wrong")
	}
}

func TestPrioritizeByDataTier_ReordersAndAttributes(t *testing.T) {
	assets := []platform.Asset{
		{ID: "crown", Target: "https://payments.acme.com"}, // tier 1 below
		{ID: "junk", Target: "https://sandbox.acme.com"},   // tier 3 below
	}
	assets[0] = assets[0].WithDataTier(platform.DataTierCritical)
	assets[1] = assets[1].WithDataTier(platform.DataTierLow)

	issues := []Issue{
		// A critical on the throwaway sandbox.
		{Key: "k1", Severity: "critical", Endpoint: "https://sandbox.acme.com/admin"},
		// A high on the customer-data payments app.
		{Key: "k2", Severity: "high", Endpoint: "https://payments.acme.com/checkout"},
		// A medium with no attributable asset → stays Standard.
		{Key: "k3", Severity: "medium", Endpoint: "internal/util.go:7"},
	}
	out := PrioritizeByDataTier(issues, assets)

	// The whole point: the HIGH on customer-data outranks the CRITICAL on the sandbox.
	if out[0].Key != "k2" {
		t.Errorf("high@customer-data should lead, got %q (ranks: %+v)", out[0].Key, []int{out[0].RiskRank, out[1].RiskRank, out[2].RiskRank})
	}
	// Attribution is recorded + grounded.
	var k1, k2, k3 Issue
	for _, i := range out {
		switch i.Key {
		case "k1":
			k1 = i
		case "k2":
			k2 = i
		case "k3":
			k3 = i
		}
	}
	if k2.DataTier != platform.DataTierCritical {
		t.Errorf("k2 should attribute to the tier-1 asset, got tier %d", k2.DataTier)
	}
	if k1.DataTier != platform.DataTierLow {
		t.Errorf("k1 should attribute to the tier-3 asset, got tier %d", k1.DataTier)
	}
	if k3.DataTier != platform.DataTierStandard {
		t.Errorf("k3 has no matching asset → Standard, got tier %d", k3.DataTier)
	}
	if k2.RiskRank <= k1.RiskRank {
		t.Errorf("k2 risk (%d) must exceed k1 risk (%d)", k2.RiskRank, k1.RiskRank)
	}
}

func TestPrioritize_ExploitabilityTiebreaker(t *testing.T) {
	// All high severity, no asset tiering → the exploitability tiebreaker is the only re-ordering:
	// attacked > confirmed > unproven.
	issues := []Issue{
		{Key: "plain", Severity: "high"},
		{Key: "confirmed", Severity: "high", Confirmed: true},
		{Key: "attacked", Severity: "high", Attacked: true},
	}
	out := PrioritizeByDataTier(issues, nil)
	got := []string{out[0].Key, out[1].Key, out[2].Key}
	want := []string{"attacked", "confirmed", "plain"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("exploitability order wrong: got %v want %v", got, want)
		}
	}

	// The tiebreaker is within-severity: a critical (even unproven) still leads an attacked high
	// (the boost is < the severity gap, so it never inflates a lesser issue past a worse one).
	mixed := PrioritizeByDataTier([]Issue{
		{Key: "attacked-high", Severity: "high", Attacked: true},
		{Key: "plain-critical", Severity: "critical"},
	}, nil)
	if mixed[0].Key != "plain-critical" {
		t.Errorf("a critical must still outrank an attacked high, got %s first", mixed[0].Key)
	}
}
