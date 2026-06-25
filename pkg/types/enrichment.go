package types

import (
	"fmt"
	"strings"
)

// This file holds the canonical, compact renderings of a finding's L1.5 enrichment (§11 hook chain:
// surface_priority, exploitability, corroborator, threat_intel, compliance, verification). The L2 Lead
// digest AND the cloud/web investigate agents all render through these, so the L1.5 → L2 hand-off
// presents the same signals everywhere — an agent triaging a finding always sees the enrichment the
// engine computed, not just the raw severity.

// L15Summary renders the threat/exploitability enrichment as a compact inline string for an agent's
// prompt — e.g. "KEV EPSS:0.94 exploit:8 surface:7 corrob:2 verified". Empty when the finding carries
// no enrichment (so a bare L1 finding reads unchanged).
func (f Finding) L15Summary() string {
	var t []string
	if ti := f.ThreatIntel; ti != nil {
		if ti.KEV != nil && ti.KEV.Listed {
			t = append(t, "KEV") // CISA actively-exploited list
		}
		if ti.EPSS != nil {
			t = append(t, fmt.Sprintf("EPSS:%.2f", ti.EPSS.Score))
		}
	}
	if f.Exploitability != nil {
		t = append(t, fmt.Sprintf("exploit:%d", f.Exploitability.Score))
	}
	if f.SurfacePriority != nil {
		t = append(t, fmt.Sprintf("surface:%d", f.SurfacePriority.Score))
	}
	if n := len(f.CorroboratedBy); n > 0 {
		t = append(t, fmt.Sprintf("corrob:%d", n))
	}
	if vs := f.VerificationStatus; vs != "" && string(vs) != "pattern_match" {
		t = append(t, string(vs)) // corroborated / verified
	}
	return strings.Join(t, " ")
}

// ComplianceSummary lists the frameworks this finding maps to (the §8 control mapping), comma-joined —
// e.g. "soc2,pci,hipaa,gdpr". Empty when no control nexus. The compliance audience (cloud especially)
// triages by which controls a finding touches, so the investigate agents surface this alongside L15Summary.
func (f Finding) ComplianceSummary() string {
	c := f.Compliance
	if c == nil {
		return ""
	}
	var fw []string
	for _, kv := range []struct {
		name string
		ctrl []string
	}{
		{"soc2", c.SOC2}, {"pci", c.PCI}, {"hipaa", c.HIPAA}, {"cis_v8", c.CISv8},
		{"nist_csf", c.NISTCSF}, {"iso27001", c.ISO27001}, {"gdpr", c.GDPR}, {"iso27701", c.ISO27701},
		{"nist_800_53", c.NIST80053}, {"nist_800_171", c.NIST800171}, {"ccpa", c.CCPA}, {"sox", c.SOX},
	} {
		if len(kv.ctrl) > 0 {
			fw = append(fw, kv.name)
		}
	}
	return strings.Join(fw, ",")
}

// L15Tag is L15Summary plus the compliance frameworks, bracket-wrapped and ready to append to a digest
// line — "  [KEV exploit:8 | soc2,pci]". Empty when the finding has no enrichment at all.
func (f Finding) L15Tag() string {
	parts := f.L15Summary()
	if c := f.ComplianceSummary(); c != "" {
		if parts != "" {
			parts += " | " + c
		} else {
			parts = c
		}
	}
	if parts == "" {
		return ""
	}
	return "  [" + parts + "]"
}
