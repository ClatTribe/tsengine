package semgrep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_Findings(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob)
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3", len(findings))
	}

	// ERROR → high, CWE-78 extracted from array form
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("severity[0]: %q, want high", findings[0].Severity)
	}
	if len(findings[0].CWE) != 1 || findings[0].CWE[0] != "CWE-78" {
		t.Errorf("CWE[0]: %v", findings[0].CWE)
	}
	if findings[0].Endpoint != "app/handlers.py:88" {
		t.Errorf("endpoint[0]: %q", findings[0].Endpoint)
	}

	// WARNING → medium, CWE-79 extracted from string form
	if findings[1].Severity != types.SeverityMedium {
		t.Errorf("severity[1]: %q, want medium", findings[1].Severity)
	}
	if findings[1].CWE[0] != "CWE-79" {
		t.Errorf("CWE[1]: %v", findings[1].CWE)
	}

	// INFO → info, no CWE
	if findings[2].Severity != types.SeverityInfo {
		t.Errorf("severity[2]: %q", findings[2].Severity)
	}
	if findings[2].CWE != nil {
		t.Errorf("CWE[2] should be nil: %v", findings[2].CWE)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]types.Severity{
		"ERROR": types.SeverityHigh, "WARNING": types.SeverityMedium,
		"INFO": types.SeverityInfo, "": types.SeverityInfo,
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestSurface(t *testing.T) {
	s := New()
	if s.Name() != "semgrep" || !s.SandboxExecution() {
		t.Errorf("surface wrong")
	}
}
