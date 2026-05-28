package gitleaks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_Secrets(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob, "/workspace")
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2", len(findings))
	}
	if findings[0].RuleID != "gitleaks::aws-access-token" {
		t.Errorf("RuleID: %q", findings[0].RuleID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("severity: %q, want high", findings[0].Severity)
	}
	if findings[0].CWE[0] != "CWE-798" {
		t.Errorf("CWE: %v", findings[0].CWE)
	}
	if findings[0].Endpoint != "config/settings.py:42" {
		t.Errorf("endpoint: %q", findings[0].Endpoint)
	}
}

func TestParse_EmptyAndNonArray(t *testing.T) {
	if parse(nil, "/x") != nil {
		t.Error("nil expected for empty")
	}
	if parse([]byte("{}"), "/x") != nil {
		t.Error("nil expected for non-array")
	}
	// gitleaks with no findings prints "[]" or nothing.
	if parse([]byte("[]"), "/x") != nil {
		t.Error("nil expected for empty array")
	}
}

func TestSurface(t *testing.T) {
	g := New()
	if g.Name() != "gitleaks" || !g.SandboxExecution() {
		t.Errorf("surface wrong: %s", g.Name())
	}
}
