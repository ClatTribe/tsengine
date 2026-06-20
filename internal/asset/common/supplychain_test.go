package common

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

// A syft CycloneDX SBOM containing a known-malicious package (ua-parser-js at a
// hijacked version) → a malicious-package finding; the clean component does not.
const sbomWithMalicious = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"name": "react", "version": "18.2.0", "purl": "pkg:npm/react@18.2.0"},
    {"name": "ua-parser-js", "version": "0.7.29", "purl": "pkg:npm/ua-parser-js@0.7.29"}
  ]
}`

const sbomClean = `{
  "bomFormat": "CycloneDX",
  "components": [
    {"name": "react", "version": "18.2.0", "purl": "pkg:npm/react@18.2.0"},
    {"name": "ua-parser-js", "version": "1.0.37", "purl": "pkg:npm/ua-parser-js@1.0.37"}
  ]
}`

func TestSupplyChainFindings_FromSBOM(t *testing.T) {
	got := SupplyChainFindings([]tool.Result{{Output: sbomWithMalicious}})
	if len(got) != 1 {
		t.Fatalf("want 1 malicious finding from the SBOM, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Tool != "malicious-packages" || f.Severity != "critical" {
		t.Errorf("finding not a critical malicious-package: %+v", f)
	}
	if f.Endpoint != "npm:ua-parser-js@0.7.29" {
		t.Errorf("endpoint should cite the coordinate, got %q", f.Endpoint)
	}
}

func TestSupplyChainFindings_CleanSBOM(t *testing.T) {
	if got := SupplyChainFindings([]tool.Result{{Output: sbomClean}}); len(got) != 0 {
		t.Errorf("clean SBOM must yield no malware findings, got %d", len(got))
	}
}

func TestSupplyChainFindings_NoSBOM(t *testing.T) {
	// Results with no CycloneDX SBOM (e.g. a nuclei output) must no-op.
	if got := SupplyChainFindings([]tool.Result{{Output: "some nuclei text output"}, {Output: 42}}); got != nil {
		t.Errorf("non-SBOM results should no-op, got %+v", got)
	}
}
