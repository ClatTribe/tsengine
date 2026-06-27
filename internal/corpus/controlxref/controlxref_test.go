package controlxref

import (
	"strings"
	"testing"
)

// A tiny SCF-shaped matrix export: columns identified by header substrings, cells carry the framework's
// control IDs (a cell may hold several). Validates header-matching, multi-id cells, and normalization.
const scfFixture = `SCF Control,SOC 2 (AICPA TSC),PCI DSS v4.0,NIST SP 800-53 R5,HIPAA
IAC-01,"CC6.1, CC6.2",8.3.1,AC-2,
CRY-03,CC6.7,"4.2.1; 3.6.1","SC-8, SC-13",164.312(e)(1)
`

func TestParse_MatchesColumnsAndCollectsControls(t *testing.T) {
	m, err := Parse(strings.NewReader(scfFixture), SCF)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m["soc2"]["CC6.1"] || !m["soc2"]["CC6.7"] {
		t.Errorf("soc2 controls not collected: %v", m["soc2"])
	}
	if !m["pci"]["8.3.1"] || !m["pci"]["4.2.1"] || !m["pci"]["3.6.1"] {
		t.Errorf("multi-id pci cell not split: %v", m["pci"])
	}
	if !m["nist_800_53"]["SC-8"] || !m["nist_800_53"]["AC-2"] {
		t.Errorf("nist_800_53 controls not collected: %v", m["nist_800_53"])
	}
	if !m["hipaa"]["164.312(E)(1)"] { // normalized uppercase
		t.Errorf("hipaa control not collected/normalized: %v", m["hipaa"])
	}
}

func TestCrossReference_GroundedCoverage(t *testing.T) {
	m, _ := Parse(strings.NewReader(scfFixture), SCF)
	ours := map[string][]string{
		"soc2": {"CC6.1", "CC6.7", "CC9.9"}, // first two corroborated by SCF, CC9.9 not → missing
		"pci":  {"8.3.1"},                   // corroborated
	}
	rep := CrossReference("SCF", ours, m)
	if rep.TotalControls != 4 || rep.Corroborated != 3 {
		t.Fatalf("want 3/4 corroborated, got %d/%d", rep.Corroborated, rep.TotalControls)
	}
	if rep.Percent != 75 {
		t.Errorf("percent want 75, got %d", rep.Percent)
	}
	// CC9.9 must be reported missing, not silently dropped (§10 honesty)
	var sawMissing bool
	for _, fc := range rep.Frameworks {
		if fc.Framework == "soc2" {
			for _, mc := range fc.Missing {
				if mc == "CC9.9" {
					sawMissing = true
				}
			}
		}
	}
	if !sawMissing {
		t.Error("an uncorroborated control must be reported as missing")
	}
}

func TestParse_MalformedHeaderEmpty(t *testing.T) {
	if m, _ := Parse(strings.NewReader(""), SCF); len(m) != 0 {
		t.Errorf("empty input → empty map, got %v", m)
	}
}
