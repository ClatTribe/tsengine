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
