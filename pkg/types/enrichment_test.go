package types

import (
	"strings"
	"testing"
)

func TestL15Summary_AndCompliance(t *testing.T) {
	f := Finding{
		Severity:           SeverityHigh,
		ThreatIntel:        &ThreatIntel{KEV: &KEVStatus{Listed: true}, EPSS: &EPSSScore{Score: 0.91}},
		Exploitability:     &Exploitability{Score: 8},
		SurfacePriority:    &SurfacePriority{Score: 6},
		CorroboratedBy:     []string{"grype", "trivy"},
		VerificationStatus: "verified",
		Compliance:         &Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"6.2"}, GDPR: []string{"Art.32"}},
	}
	sum := f.L15Summary()
	for _, want := range []string{"KEV", "EPSS:0.91", "exploit:8", "surface:6", "corrob:2", "verified"} {
		if !strings.Contains(sum, want) {
			t.Errorf("L15Summary missing %q: %s", want, sum)
		}
	}
	comp := f.ComplianceSummary()
	for _, want := range []string{"soc2", "pci", "gdpr"} {
		if !strings.Contains(comp, want) {
			t.Errorf("ComplianceSummary missing %q: %s", want, comp)
		}
	}
	tag := f.L15Tag()
	if !strings.Contains(tag, "KEV") || !strings.Contains(tag, "soc2") || tag[:3] != "  [" {
		t.Errorf("L15Tag should bracket-wrap enrichment + compliance: %q", tag)
	}

	// pattern_match verification is NOT surfaced (it's the un-upgraded default); a bare finding → empty.
	bare := Finding{Severity: SeverityLow, VerificationStatus: "pattern_match"}
	if bare.L15Summary() != "" || bare.L15Tag() != "" {
		t.Errorf("a bare finding should have empty L1.5 summary/tag, got %q / %q", bare.L15Summary(), bare.L15Tag())
	}
}
