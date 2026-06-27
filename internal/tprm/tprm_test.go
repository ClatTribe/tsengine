package tprm

import (
	"testing"
	"time"
)

func TestAssess_VendorRisks(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	vendors := []Vendor{
		{Name: "AnalyticsCo", DataAccess: DataPII},                                              // uncertified data vendor
		{Name: "DataPipe", Subprocessor: true, DataAccess: DataPII, Certifications: []string{"SOC2"}}, // subprocessor no DPA
		{Name: "OldCRM", DataAccess: DataSensitive, Breached: true, BreachNote: "2024 leak", Certifications: []string{"ISO27001"}}, // breach + data
		{Name: "PayGate", HandlesCardData: true, DataAccess: DataSensitive, Certifications: []string{"SOC2"}}, // card no PCI
		{Name: "CoreInfra", Criticality: "critical", DataAccess: DataMetadata, Certifications: []string{"SOC2"}, LastAssessed: "2024-01-01"}, // stale review
	}
	got := map[string]bool{}
	for _, f := range Assess(vendors, Options{Now: now}) {
		got[f.RuleID] = true
		if f.Compliance == nil {
			t.Errorf("%s missing compliance", f.RuleID)
		}
	}
	for _, want := range []string{
		"tprm::vendor-uncertified", "tprm::subprocessor-no-dpa", "tprm::vendor-breach-history",
		"tprm::card-vendor-no-pci", "tprm::vendor-stale-review",
	} {
		if !got[want] {
			t.Errorf("expected vendor-risk finding %q", want)
		}
	}
}

// A well-managed vendor portfolio yields ZERO findings (grounded, not noise).
func TestAssess_CleanPortfolio(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC) }
	good := []Vendor{
		{Name: "AWS", DataAccess: DataSensitive, Subprocessor: true, HasDPA: true, Certifications: []string{"SOC2", "ISO27001", "PCI"}, HandlesCardData: true, Criticality: "critical", LastAssessed: "2026-05-01"},
		{Name: "Logger", DataAccess: DataMetadata, Certifications: []string{"SOC2"}, Criticality: "low"},
	}
	if f := Assess(good, Options{Now: now}); len(f) != 0 {
		t.Errorf("a well-managed portfolio must yield zero findings, got %d: %+v", len(f), f)
	}
}
