package supplychain

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func eolRules(fs []types.Finding) map[string]types.Finding {
	m := map[string]types.Finding{}
	for _, f := range fs {
		m[f.RuleID] = f
	}
	return m
}

// A past-EOL runtime/framework is flagged high; a supported one is clean.
func TestScanEOL_PastEOLFlaggedSupportedClean(t *testing.T) {
	now := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	pkgs := []Package{
		{Ecosystem: "pypi", Name: "django", Version: "2.2.28"}, // EOL 2022-04-11 → past
		{Ecosystem: "deb", Name: "python", Version: "2.7.18"},  // EOL 2020 → past
		{Ecosystem: "pypi", Name: "django", Version: "5.0.1"},  // supported → clean
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},   // not in EOL corpus → clean
	}
	got := eolRules(ScanEOL(pkgs, DefaultEOLCorpus(), now))
	for _, want := range []string{"eol::django-2.2", "eol::python-2.7"} {
		f, ok := got[want]
		if !ok {
			t.Errorf("missing past-EOL finding %q", want)
			continue
		}
		if f.Severity != types.SeverityHigh || f.Tool != "eol" || len(f.CWE) == 0 || f.CWE[0] != "CWE-1104" {
			t.Errorf("%s not grounded as high/CWE-1104: %+v", want, f)
		}
		if f.Compliance == nil || len(f.Compliance.CISv8) == 0 {
			t.Errorf("%s must be compliance-mapped: %+v", want, f)
		}
	}
	if _, bad := got["eol::django-5.0"]; bad {
		t.Error("a supported Django must not be flagged")
	}
}

// A version-cycle reaching EOL within the heads-up window is a medium heads-up.
func TestScanEOL_ApproachingIsMedium(t *testing.T) {
	// php 8.1 EOL 2025-12-31; assess 60 days before → medium heads-up.
	now := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	got := eolRules(ScanEOL([]Package{{Ecosystem: "deb", Name: "php", Version: "8.1.20"}}, DefaultEOLCorpus(), now))
	f, ok := got["eol::php-8.1"]
	if !ok || f.Severity != types.SeverityMedium {
		t.Errorf("approaching-EOL php 8.1 should be a medium heads-up, got %+v", f)
	}
	if !strings.Contains(f.Description, "reaches end-of-life") {
		t.Errorf("heads-up wording expected: %q", f.Description)
	}
}

// Name aliases resolve (node → nodejs); version-cycle matching is exact-prefix.
func TestScanEOL_AliasAndCyclePrefix(t *testing.T) {
	now := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	// "node" alias + cycle "12" matches 12.x but NOT 120.x.
	if got := ScanEOL([]Package{{Name: "node", Version: "12.22.1"}}, DefaultEOLCorpus(), now); len(got) != 1 {
		t.Errorf("node 12.22.1 should match nodejs 12 EOL, got %d", len(got))
	}
	if got := ScanEOL([]Package{{Name: "node", Version: "120.0.0"}}, DefaultEOLCorpus(), now); len(got) != 0 {
		t.Errorf("node 120.0.0 must NOT match cycle 12, got %d", len(got))
	}
}
