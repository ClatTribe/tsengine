package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestThreatIntel_EnrichesKEVCVE(t *testing.T) {
	h := NewThreatIntel()
	out, audit, keep := h.Apply(mkFinding("f-1", "trivy::CVE-2021-44228", types.SeverityCritical, "CWE-502"))
	if !keep {
		t.Fatal("dropped")
	}
	if out.ThreatIntel == nil {
		t.Fatal("no threat_intel annotation")
	}
	if out.ThreatIntel.CVSS != 10.0 {
		t.Errorf("CVSS: got %v, want 10.0", out.ThreatIntel.CVSS)
	}
	if out.ThreatIntel.KEV == nil || !out.ThreatIntel.KEV.Listed {
		t.Error("Log4Shell should be KEV-listed")
	}
	if out.ThreatIntel.EPSS == nil || out.ThreatIntel.EPSS.Score < 0.9 {
		t.Errorf("EPSS too low: %+v", out.ThreatIntel.EPSS)
	}
	// KEV listing must be audited.
	if len(audit) != 1 || audit[0].Rule != "threat_intel::kev-listed" {
		t.Errorf("KEV listing not audited: %+v", audit)
	}
}

func TestThreatIntel_NonKEVCVENoAudit(t *testing.T) {
	h := NewThreatIntel()
	out, audit, _ := h.Apply(mkFinding("f-1", "trivy::CVE-2021-42374", types.SeverityMedium, "CWE-125"))
	if out.ThreatIntel == nil {
		t.Fatal("should still enrich a non-KEV CVE")
	}
	if out.ThreatIntel.KEV != nil && out.ThreatIntel.KEV.Listed {
		t.Error("CVE-2021-42374 should not be KEV-listed")
	}
	if len(audit) != 0 {
		t.Errorf("non-KEV CVE should not audit: %+v", audit)
	}
}

func TestThreatIntel_NoCVENoOp(t *testing.T) {
	h := NewThreatIntel()
	out, audit, keep := h.Apply(mkFinding("f-1", "nuclei::missing-headers", types.SeverityInfo, "CWE-693"))
	if !keep {
		t.Fatal("dropped")
	}
	if out.ThreatIntel != nil {
		t.Error("no CVE → no threat_intel annotation")
	}
	if len(audit) != 0 {
		t.Errorf("no audit expected: %+v", audit)
	}
}

func TestThreatIntel_UnknownCVENoOp(t *testing.T) {
	h := NewThreatIntel()
	out, _, _ := h.Apply(mkFinding("f-1", "trivy::CVE-1999-99999", types.SeverityLow))
	if out.ThreatIntel != nil {
		t.Error("unknown CVE → no annotation (graceful)")
	}
}

func TestCompliance_MapsCWE(t *testing.T) {
	h := NewCompliance()
	out, _, keep := h.Apply(mkFinding("f-1", "nuclei::sqli", types.SeverityHigh, "CWE-89"))
	if !keep {
		t.Fatal("dropped")
	}
	if out.Compliance == nil {
		t.Fatal("no compliance annotation")
	}
	if len(out.Compliance.SOC2) == 0 || len(out.Compliance.PCI) == 0 {
		t.Errorf("CWE-89 should map to SOC2 + PCI: %+v", out.Compliance)
	}
}

// The expanded framework set (CLAUDE.md §8) must actually map, not just exist as struct
// fields — a finding's CWE has to land on the new privacy/government controls.
func TestCompliance_MapsExpandedFrameworks(t *testing.T) {
	h := NewCompliance()
	// CWE-200 (data exposure) is the broadest privacy nexus: GDPR, CCPA, NIST 800-53,
	// FedRAMP, DPDP, SOX, ISO 27701 all apply.
	out, _, _ := h.Apply(mkFinding("f-1", "nuclei::info-exposure", types.SeverityHigh, "CWE-200"))
	if out.Compliance == nil {
		t.Fatal("CWE-200 produced no compliance annotation")
	}
	c := out.Compliance
	checks := map[string][]string{
		"GDPR": c.GDPR, "NIST 800-53": c.NIST80053, "NIST 800-171": c.NIST800171,
		"CCPA": c.CCPA, "FedRAMP": c.FedRAMP, "DPDP": c.DPDP, "SOX": c.SOX, "ISO 27701": c.ISO27701,
	}
	for name, ids := range checks {
		if len(ids) == 0 {
			t.Errorf("CWE-200 should map to %s, got none: %+v", name, c)
		}
	}
}

// The PROVEN apiauthz findings (BOLA CWE-639, BFLA CWE-285, mass-assignment CWE-915) emit as
// verification_status=verified — the most-confident findings the engine produces. Before the crosswalk
// expansion they mapped to ZERO controls, so a proven authz bypass moved no framework to "gap" (a false
// "compliant"). This guards the fix: each must land on access-control controls across the frameworks.
func TestCompliance_MapsAuthzFamily(t *testing.T) {
	h := NewCompliance()
	for _, cwe := range []string{"CWE-639", "CWE-285", "CWE-915", "CWE-862", "CWE-863"} {
		out, _, keep := h.Apply(mkFinding("f-1", "apiauthz::"+cwe, types.SeverityHigh, cwe))
		if !keep || out.Compliance == nil {
			t.Fatalf("%s: dropped or no compliance annotation", cwe)
		}
		c := out.Compliance
		if len(c.SOC2) == 0 || len(c.PCI) == 0 || len(c.NIST80053) == 0 || len(c.NISTCSF) == 0 {
			t.Errorf("%s (broken authorization) should map to SOC2+PCI+NIST access controls, got %+v", cwe, c)
		}
	}
	// BOLA additionally exposes data → privacy controls must apply (GDPR/CCPA/DPDP).
	out, _, _ := h.Apply(mkFinding("f-2", "apiauthz::bola", types.SeverityHigh, "CWE-639"))
	if len(out.Compliance.GDPR) == 0 || len(out.Compliance.CCPA) == 0 {
		t.Errorf("CWE-639 (BOLA, data exposure) should map to GDPR + CCPA, got %+v", out.Compliance)
	}
}

// A non-CWE emission path (sspm/operate/cloud) sets an inline, source-specific mapping AND now also
// carries a weakness CWE. The hook must MERGE the crosswalk into the inline mapping — keep the SaaS-
// specific control AND gain the framework set the CWE maps to — never clobber it (the coverage fix).
func TestCompliance_MergesInlineMappingWithCWE(t *testing.T) {
	h := NewCompliance()
	in := types.Finding{
		RuleID:     "sspm::slack::2fa-not-enforced",
		Tool:       "sspm",
		Severity:   types.SeverityHigh,
		CWE:        []string{"CWE-287"}, // authentication
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"8.4.2"}, CISv8: []string{"6.5"}},
	}
	out, _, keep := h.Apply(in)
	if !keep || out.Compliance == nil {
		t.Fatal("dropped or no compliance")
	}
	c := out.Compliance
	// the SaaS-specific inline controls survive
	if !contains(c.PCI, "8.4.2") || !contains(c.CISv8, "6.5") {
		t.Errorf("inline SaaS controls were clobbered: %+v", c)
	}
	// AND the crosswalk's CWE-287 frameworks are now present (HIPAA/ISO27001/NIST/FedRAMP/SOX)
	if len(c.HIPAA) == 0 || len(c.ISO27001) == 0 || len(c.NIST80053) == 0 || len(c.FedRAMP) == 0 {
		t.Errorf("CWE-287 crosswalk frameworks not merged in: %+v", c)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestCompliance_MergesMultipleCWE(t *testing.T) {
	h := NewCompliance()
	// CWE-89 + CWE-200 both map; controls should union without dupes.
	out, _, _ := h.Apply(mkFinding("f-1", "x", types.SeverityHigh, "CWE-89", "CWE-200"))
	if out.Compliance == nil {
		t.Fatal("no annotation")
	}
	// SOC2 CC6.1 appears in both → must not duplicate.
	count := 0
	for _, c := range out.Compliance.SOC2 {
		if c == "CC6.1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("CC6.1 duplicated %d times: %v", count, out.Compliance.SOC2)
	}
}

func TestCompliance_NoCWENoOp(t *testing.T) {
	h := NewCompliance()
	out, _, _ := h.Apply(mkFinding("f-1", "x", types.SeverityInfo))
	if out.Compliance != nil {
		t.Error("no CWE → no compliance annotation")
	}
}

func TestCompliance_UnknownCWENoOp(t *testing.T) {
	h := NewCompliance()
	out, _, _ := h.Apply(mkFinding("f-1", "x", types.SeverityLow, "CWE-99999"))
	if out.Compliance != nil {
		t.Error("unknown CWE → no annotation")
	}
}

// A CVE finding with NO CWE (the SCA/container case from grype/trivy) must still map to vulnerability-
// management controls — proven on a real alpine scan where such findings were getting compliance:none.
func TestCompliance_CVEWithoutCWEMapsVulnMgmt(t *testing.T) {
	h := NewCompliance()
	out, _, _ := h.Apply(mkFinding("f-1", "grype::CVE-2025-60876", types.SeverityHigh)) // no CWE
	if out.Compliance == nil {
		t.Fatal("a CVE finding must map to vulnerability-management controls even without a CWE")
	}
	// the grounded vuln-mgmt nexus across frameworks
	if len(out.Compliance.SOC2) == 0 || len(out.Compliance.PCI) == 0 || len(out.Compliance.ISO27001) == 0 || len(out.Compliance.NIST80053) == 0 {
		t.Errorf("CVE should map to SOC2/PCI/ISO27001/NIST 800-53 vuln-mgmt controls, got %+v", out.Compliance)
	}
	// privacy/AI frameworks have no vuln-mgmt nexus → stay empty (honest, never padded)
	if len(out.Compliance.GDPR) != 0 || len(out.Compliance.ISO42001) != 0 {
		t.Errorf("vuln-mgmt must not pad privacy/AI frameworks, got GDPR=%v ISO42001=%v", out.Compliance.GDPR, out.Compliance.ISO42001)
	}
}
