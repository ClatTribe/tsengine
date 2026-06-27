package safechain

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/supplychain"
)

func corpus() []supplychain.MaliciousPackage { return supplychain.DefaultCorpus() }

// A known-malicious version is BLOCKED at install time, with a reason + provenance.
func TestCheck_BlocksKnownMalicious(t *testing.T) {
	v := Check(supplychain.Package{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.7.29"}, corpus())
	if v.Allowed {
		t.Fatal("a known-hijacked version must be blocked")
	}
	if v.Reason == "" || v.Advisory == "" {
		t.Errorf("a block must carry a reason + advisory: %+v", v)
	}
	if v.Package != "npm:ua-parser-js@0.7.29" {
		t.Errorf("coordinate: %q", v.Package)
	}
}

// A SAFE version of the SAME package (not in the pinned malicious set) is allowed — version-aware.
func TestCheck_AllowsCleanVersionOfHijackedPackage(t *testing.T) {
	if v := Check(supplychain.Package{Ecosystem: "npm", Name: "ua-parser-js", Version: "1.0.33"}, corpus()); !v.Allowed {
		t.Fatalf("a non-malicious version must be allowed, got %+v", v)
	}
}

// Grounded §10: an unknown package is ALLOWED (fail-open) — the guard never blocks on absence of proof.
func TestCheck_AllowsUnknown(t *testing.T) {
	if v := Check(supplychain.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, corpus()); !v.Allowed {
		t.Fatalf("an unknown package must be allowed, got %+v", v)
	}
}

// A batch is unsafe iff ANY package is blocked; the roll-up counts correctly.
func TestCheckAll_RollsUp(t *testing.T) {
	pkgs := []supplychain.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},      // safe
		{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.7.29"}, // malicious
		{Ecosystem: "pypi", Name: "ctx", Version: "0.2.2"},          // malicious
	}
	r := CheckAll(pkgs, corpus())
	if r.Checked != 3 || r.Blocked != 2 || r.Safe {
		t.Fatalf("roll-up: %+v", r)
	}
}

func TestCheckAll_AllSafe(t *testing.T) {
	r := CheckAll([]supplychain.Package{{Ecosystem: "npm", Name: "react", Version: "18.2.0"}}, corpus())
	if !r.Safe || r.Blocked != 0 {
		t.Fatalf("an all-clean manifest must be safe, got %+v", r)
	}
}
