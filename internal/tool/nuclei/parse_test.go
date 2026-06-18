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

func TestCweFromTemplate_DastInference(t *testing.T) {
	cases := []struct {
		id, name string
		tags     []string
		want     string // "" → expect nil
	}{
		{"dast/vulnerabilities/lfi/path-traversal", "Path Traversal", []string{"dast", "traversal"}, "CWE-22"},
		{"dast/vulnerabilities/redirect/open-redirect", "Open Redirect", []string{"dast", "redirect"}, "CWE-601"},
		{"fuzz/ssrf-detect", "SSRF", []string{"ssrf"}, "CWE-918"},
		{"sqli/error-based", "Error-based SQL Injection", []string{"sqli"}, "CWE-89"},
		{"xss-reflected", "Reflected Cross-Site-Scripting", []string{"xss"}, "CWE-79"},
		{"os-command-injection", "Command Injection", []string{"cmdi"}, "CWE-78"},
		{"weak-tls", "Weak TLS", []string{"tls"}, ""}, // no class keyword → nil (parity with existing fixture)
	}
	for _, c := range cases {
		ev := jsonlEvent{TemplateID: c.id}
		ev.Info.Name = c.name
		ev.Info.Tags = c.tags
		got := cweFromTemplate(ev)
		if c.want == "" {
			if got != nil {
				t.Errorf("%s: want nil, got %v", c.id, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: want [%s], got %v", c.id, c.want, got)
		}
	}
}

func TestParseJSONL_InfersCWEWhenClassificationEmpty(t *testing.T) {
	// A generic -dast path-traversal hit with NO classification.cwe-id: the
	// parser must now infer CWE-22 (the WAVSEP pathtraver credit gap).
	line := `{"template-id":"dast/path-traversal","info":{"name":"Path Traversal","tags":["dast","traversal"],"severity":"high"},"host":"http://t","matched-at":"http://t/download?file=","type":"http","matcher-status":true}`
	f := parseJSONL([]byte(line))
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	if len(f[0].CWE) != 1 || f[0].CWE[0] != "CWE-22" {
		t.Errorf("inferred CWE: want [CWE-22], got %v", f[0].CWE)
	}
}

func TestParseJSONL_ClassificationWinsOverInference(t *testing.T) {
	// template-id contains "rce" (→ CWE-78 by inference) but the template DOES
	// carry a classification (cwe-918). Classification must win — inference is
	// only a last resort.
	line := `{"template-id":"some-rce-check","info":{"name":"X","tags":["rce"],"severity":"high","classification":{"cwe-id":["cwe-918"]}},"host":"http://t","matched-at":"http://t/x","type":"http","matcher-status":true}`
	f := parseJSONL([]byte(line))
	if len(f) != 1 || len(f[0].CWE) != 1 || f[0].CWE[0] != "CWE-918" {
		t.Fatalf("classification should win: got %v", f[0].CWE)
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
