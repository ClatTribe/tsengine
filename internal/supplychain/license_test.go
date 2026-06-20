package supplychain

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestScanLicenses_CopyleftFlaggedPermissiveClean(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "npm", Name: "saas-lib", Version: "1.0.0", License: "AGPL-3.0"},    // medium
		{Ecosystem: "pypi", Name: "gpl-tool", Version: "2.0", License: "GPL-2.0-only"}, // low
		{Ecosystem: "npm", Name: "weak", Version: "1.0", License: "LGPL-3.0"},          // not flagged
		{Ecosystem: "npm", Name: "react", Version: "18.2.0", License: "MIT"},           // clean
		{Ecosystem: "npm", Name: "nolic", Version: "1.0", License: ""},                 // no license → not flagged
	}
	got := map[string]types.Finding{}
	for _, f := range ScanLicenses(pkgs, time.Unix(0, 0)) {
		got[f.RuleID] = f
	}
	if len(got) != 2 {
		t.Fatalf("want exactly 2 license findings (AGPL + GPL), got %d: %+v", len(got), got)
	}
	if f := got["license::agpl"]; f.Severity != types.SeverityMedium || !strings.Contains(f.Description, "network copyleft") {
		t.Errorf("AGPL should be a medium network-copyleft finding: %+v", f)
	}
	if f := got["license::gpl"]; f.Severity != types.SeverityLow {
		t.Errorf("GPL should be low: %+v", f)
	}
	for _, f := range got {
		if f.Tool != "license" || f.Compliance == nil || len(f.Compliance.CISv8) == 0 {
			t.Errorf("license finding not grounded/mapped: %+v", f)
		}
		if !strings.Contains(f.Endpoint, "@") {
			t.Errorf("should cite the coordinate: %q", f.Endpoint)
		}
	}
}

func TestPackagesFromSBOM_CapturesLicense(t *testing.T) {
	sbom := `{"bomFormat":"CycloneDX","components":[
		{"name":"x","version":"1","purl":"pkg:npm/x@1","licenses":[{"license":{"id":"AGPL-3.0"}}]},
		{"name":"y","version":"2","purl":"pkg:npm/y@2","licenses":[{"expression":"MIT OR Apache-2.0"}]}
	]}`
	pkgs := PackagesFromSBOM(sbom)
	if len(pkgs) != 2 || pkgs[0].License != "AGPL-3.0" || pkgs[1].License != "MIT OR Apache-2.0" {
		t.Errorf("license not captured from SBOM: %+v", pkgs)
	}
}
