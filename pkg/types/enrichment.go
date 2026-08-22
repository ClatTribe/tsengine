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
			t = append(t, "KEV") // CISA actively-exploited list (seen in the wild)
			// RANSOMWARE is a strictly stronger claim than KEV and rides ALONGSIDE it
			// rather than replacing it: the agent should see both that this is exploited
			// in the wild and that the crews exploiting it encrypt estates. Most of the
			// KEV catalog is the former only.
			if ti.KEV.Ransomware {
				t = append(t, "RANSOMWARE")
			}
			if !ti.KEV.DueDate.IsZero() {
				// CISA's own remediation deadline, absolute. An agent prioritising work
				// should know the authority already set a date rather than infer one.
				t = append(t, "cisa-due:"+ti.KEV.DueDate.Format("2006-01-02"))
			}
		}
		if ti.EPSS != nil {
			t = append(t, fmt.Sprintf("EPSS:%.2f", ti.EPSS.Score))
		}
		if len(ti.Exploits) > 0 {
			t = append(t, "pub-exploit") // a public exploit/PoC EXISTS (ExploitDB) — patch-priority signal between EPSS and KEV
			// WEAPONIZED is a rung above, and rides ALONGSIDE pub-exploit rather than
			// replacing it. A proof-of-concept usually targets one build and needs a
			// shellcode swap or an offset recalculated before it does anything; a
			// Metasploit module is use/set/run, usable by an operator who could not write
			// the exploit and does not need to understand it. That is the difference
			// between "someone capable could" and "anyone can, tonight", and for deciding
			// what to patch first it is the whole question. Still not KEV: weaponized is
			// not evidence of exploitation in the wild.
			for _, ref := range ti.Exploits {
				if strings.HasPrefix(ref, "metasploit:") {
					// Metasploit's own reliability name for the best module, when we have
					// it: "weaponized:excellent" is a materially different fact from
					// "weaponized:manual", and it discriminates in practice rather than
					// sitting at the top — EternalBlue is AVERAGE because it can crash the
					// target, while the Log4Shell modules are excellent. A defender
					// choosing what to patch first should not have to treat those alike.
					//
					// It rates the MODULE, not this instance's exposure.
					if ti.WeaponRank != "" {
						t = append(t, "weaponized:"+ti.WeaponRank)
					} else {
						t = append(t, "weaponized")
					}
					break
				}
			}
		}
		if ti.SSVC != nil {
			// CISA's own decision points, tagged separately from KEV because they answer different
			// questions and reach different CVEs. Automatable is the one no other feed provides —
			// whether an attacker can automate the kill chain — so it is tagged even when the answer
			// is "no", which is itself informative when ranking two otherwise-identical CVEs.
			if a := ti.SSVC.Automatable; a != "" {
				t = append(t, "ssvc-automatable:"+a)
			}
			// Exploitation is CISA's read, and it is NOT KEV: a CVE can be assessed here and never
			// listed there. Tagged only when it says something beyond "none", so the digest does not
			// carry a line for every assessed CVE.
			if e := ti.SSVC.Exploitation; e != "" && e != "none" {
				t = append(t, "ssvc-exploitation:"+e)
			}
			if ti.SSVC.TechnicalImpact == "total" {
				t = append(t, "ssvc-impact:total")
			}
		}
		// ThreatIntel.Advisories is deliberately NOT tagged here, and the omission is considered
		// rather than an oversight: this line ranks, and a vendor advisory URL carries no ranking
		// information — every CVE in the KEV catalogue has one. It belongs where a responder acts,
		// which is the finding page, and it is reachable to an agent through query_threat_intel.
		// Adding six URLs to a compact priority digest would cost the agent context and tell it
		// nothing about what to do first.
		if strings.Contains(ti.CVSSVector, "AV:N") {
			t = append(t, "av:network") // NVD CVSS vector says network-attackable (no local access needed) — the strongest reachability signal
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
