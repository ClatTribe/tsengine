package dalfox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseAny_ArrayFormat(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample_array.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseAny(blob)
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2 (empty entry skipped)", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("Severity[0]: got %q, want high", findings[0].Severity)
	}
	if findings[0].CWE[0] != "CWE-79" {
		t.Errorf("CWE[0]: got %v", findings[0].CWE)
	}
	if findings[0].RuleID != "dalfox::verified-xss::inHTML-URL" {
		t.Errorf("RuleID[0]: got %q", findings[0].RuleID)
	}
	if findings[1].RuleID != "dalfox::reflected-xss::inHTML-attribute" {
		t.Errorf("RuleID[1]: got %q", findings[1].RuleID)
	}
	// "cwe-79" should be canonicalized to "CWE-79" on entry 1.
	if findings[1].CWE[0] != "CWE-79" {
		t.Errorf("CWE[1] not canonicalized: got %v", findings[1].CWE)
	}
}

func TestParseAny_JSONL(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseAny(blob)
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("Severity[0]: got %q", findings[0].Severity)
	}
}

func TestParseAny_EmptyBlob(t *testing.T) {
	if got := parseAny(nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
	if got := parseAny([]byte("  ")); got != nil {
		t.Errorf("expected nil for whitespace, got %v", got)
	}
}

func TestNormalizeSeverity_DalfoxValues(t *testing.T) {
	cases := map[string]types.Severity{
		"High":     types.SeverityHigh,
		"HIGH":     types.SeverityHigh,
		"Medium":   types.SeverityMedium,
		"Low":      types.SeverityLow,
		"Info":     types.SeverityInfo,
		"":         types.SeverityInfo,
		"weird":    types.SeverityInfo,
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeCWE_FromDalfox(t *testing.T) {
	if got := normalizeCWE(""); got != nil {
		t.Errorf("nil expected for empty, got %v", got)
	}
	if got := normalizeCWE("cwe-79"); len(got) != 1 || got[0] != "CWE-79" {
		t.Errorf("canonicalization: got %v", got)
	}
	if got := normalizeCWE("CWE-79"); len(got) != 1 || got[0] != "CWE-79" {
		t.Errorf("already-canonical: got %v", got)
	}
}

func TestDalfoxTool_Surface(t *testing.T) {
	d := New()
	if d.Name() != "dalfox" {
		t.Errorf("Name: %q", d.Name())
	}
	if !d.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
}
