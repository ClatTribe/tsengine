package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseJSONL_FixtureSample(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	findings := parseJSONL(blob)
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3 (template-id empty + non-json lines should be skipped)", len(findings))
	}

	// First: missing security headers (info severity, CWE-693)
	f := findings[0]
	if f.RuleID != "nuclei::http-missing-security-headers" {
		t.Errorf("RuleID: got %q", f.RuleID)
	}
	if f.Severity != types.SeverityInfo {
		t.Errorf("Severity: got %q, want info", f.Severity)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-693" {
		t.Errorf("CWE: got %v, want [CWE-693]", f.CWE)
	}
	if f.Endpoint != "https://example.com" {
		t.Errorf("Endpoint: got %q", f.Endpoint)
	}

	// Second: Spring4Shell — critical, multiple CWEs (one lowercased,
	// dedupe-preserved order)
	f = findings[1]
	if f.Severity != types.SeverityCritical {
		t.Errorf("Severity: got %q, want critical", f.Severity)
	}
	if len(f.CWE) != 2 {
		t.Errorf("CWE: got %v, want 2 entries", f.CWE)
	}
	if f.CWE[0] != "CWE-78" || f.CWE[1] != "CWE-94" {
		t.Errorf("CWE normalization wrong: %v", f.CWE)
	}
	if f.Endpoint != "https://example.com/path?x=1" {
		t.Errorf("Endpoint should prefer matched-at over host: got %q", f.Endpoint)
	}
	if f.Title != "Spring4Shell RCE" {
		t.Errorf("Title: got %q", f.Title)
	}

	// Third: weak-tls — medium severity, network type, no CWE
	f = findings[2]
	if f.Severity != types.SeverityMedium {
		t.Errorf("Severity: got %q, want medium", f.Severity)
	}
	if f.Endpoint != "example.com:443" {
		t.Errorf("Endpoint: got %q", f.Endpoint)
	}
	if f.CWE != nil {
		t.Errorf("CWE: got %v, want nil for no-cwe finding", f.CWE)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]types.Severity{
		"critical":      types.SeverityCritical,
		"CRITICAL":      types.SeverityCritical,
		"high":          types.SeverityHigh,
		"medium":        types.SeverityMedium,
		"low":           types.SeverityLow,
		"info":          types.SeverityInfo,
		"informational": types.SeverityInfo,
		"":              types.SeverityInfo,
		"unknown":       types.SeverityInfo,
		" HIGH ":        types.SeverityHigh,
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCWE_DedupeAndCanon(t *testing.T) {
	in := []string{"cwe-89", "CWE-89", "cwe-94", "", "  ", "CWE-693"}
	out := normalizeCWE(in)
	want := []string{"CWE-89", "CWE-94", "CWE-693"}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("idx %d: got %q, want %q", i, out[i], want[i])
		}
	}
}

func TestNormalizeCWE_EmptyInput(t *testing.T) {
	if normalizeCWE(nil) != nil {
		t.Error("expected nil from nil input")
	}
	if normalizeCWE([]string{}) != nil {
		t.Error("expected nil from empty input")
	}
}

func TestParseJSONL_HandlesEmptyBlob(t *testing.T) {
	if got := parseJSONL(nil); got != nil {
		t.Errorf("expected nil from nil blob, got %v", got)
	}
	if got := parseJSONL([]byte("")); got != nil {
		t.Errorf("expected nil from empty blob, got %v", got)
	}
}

func TestNucleiTool_RegisteredAndStable(t *testing.T) {
	// The package init() registers nuclei. Just verify the Tool surface.
	n := New()
	if n.Name() != "nuclei" {
		t.Errorf("Name: %q", n.Name())
	}
	if !n.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
	if len(n.MITRETechniques()) == 0 {
		t.Error("MITRETechniques should not be empty")
	}
}
