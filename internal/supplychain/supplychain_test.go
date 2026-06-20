package supplychain

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A clean dependency set yields ZERO findings (determinism / no false positives).
func TestScan_CleanDepsAreClean(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},
		{Ecosystem: "npm", Name: "ua-parser-js", Version: "1.0.37"}, // legit, NOT a malicious version
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},    // the real one, not the typosquat
		{Ecosystem: "npm", Name: "colors", Version: "1.4.0"},        // pre-sabotage version
	}
	if f := Scan(pkgs, DefaultCorpus(), Options{Now: time.Unix(0, 0)}); len(f) != 0 {
		t.Errorf("clean deps must be clean, got %d: %+v", len(f), f)
	}
}

// Malicious matches are flagged critical, grounded, and compliance-mapped.
func TestScan_FlagsMaliciousPackages(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.7.29"}, // hijacked version
		{Ecosystem: "pypi", Name: "jeIlyfish", Version: "0.7.1"},    // typosquat — any version
		{Ecosystem: "pypi", Name: "request", Version: "1.0.0"},      // typosquat of requests
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},        // clean — must not flag
	}
	got := Scan(pkgs, DefaultCorpus(), Options{Now: time.Unix(0, 0)})
	if len(got) != 3 {
		t.Fatalf("want 3 malicious findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity != types.SeverityCritical {
			t.Errorf("malicious package must be critical: %+v", f)
		}
		if f.Tool != "malicious-packages" || len(f.CWE) == 0 || f.CWE[0] != "CWE-506" {
			t.Errorf("finding not grounded as embedded-malicious-code (CWE-506): %+v", f)
		}
		if f.Compliance == nil || len(f.Compliance.CISv8) == 0 {
			t.Errorf("malicious finding must be compliance-mapped: %+v", f)
		}
		if f.VerificationStatus != types.VerificationVerified {
			t.Errorf("corpus match is a verified fact: %+v", f)
		}
		if !strings.Contains(f.Endpoint, "@") {
			t.Errorf("finding should cite the package coordinate: %q", f.Endpoint)
		}
	}
}

// A hijacked package is only malicious at the affected versions — a later fixed
// version must NOT be flagged (no false positive on the recovered package).
func TestScan_HijackVersionScoping(t *testing.T) {
	bad := Scan([]Package{{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.8.0"}}, DefaultCorpus(), Options{})
	if len(bad) != 1 {
		t.Errorf("hijacked version 0.8.0 should be flagged, got %d", len(bad))
	}
	ok := Scan([]Package{{Ecosystem: "npm", Name: "ua-parser-js", Version: "1.0.37"}}, DefaultCorpus(), Options{})
	if len(ok) != 0 {
		t.Errorf("recovered version 1.0.37 must NOT be flagged, got %d", len(ok))
	}
}

// Matching is case-insensitive on ecosystem + name.
func TestScan_CaseInsensitive(t *testing.T) {
	got := Scan([]Package{{Ecosystem: "PyPI", Name: "Request", Version: "9"}}, DefaultCorpus(), Options{})
	if len(got) != 1 {
		t.Errorf("case-insensitive match expected, got %d", len(got))
	}
}
