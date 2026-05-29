package adapters

import (
	"strings"
	"testing"
)

func TestCompliance_MapKnownCWE(t *testing.T) {
	a := NewCompliance()
	// CWE-89 (SQLi) is in the pinned corpus.
	out := a.MapCWE([]string{"CWE-89"})
	if out == "" {
		t.Fatal("CWE-89 should map to controls")
	}
	if !strings.Contains(out, "CWE-89") {
		t.Errorf("mapping should cite the CWE: %s", out)
	}
	// At least one framework label should appear.
	frameworks := []string{"SOC2", "PCI", "HIPAA", "CIS-v8", "NIST-CSF", "ISO-27001"}
	named := false
	for _, fw := range frameworks {
		if strings.Contains(out, fw) {
			named = true
			break
		}
	}
	if !named {
		t.Errorf("mapping should name at least one framework: %s", out)
	}
}

func TestCompliance_UnknownCWE(t *testing.T) {
	a := NewCompliance()
	if out := a.MapCWE([]string{"CWE-99999"}); out != "" {
		t.Errorf("an unmapped CWE should return empty, got %q", out)
	}
}

func TestCompliance_EmptyInput(t *testing.T) {
	a := NewCompliance()
	if out := a.MapCWE(nil); out != "" {
		t.Errorf("no CWEs should return empty, got %q", out)
	}
}
