package trufflehog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_VerifiedVsUnverified(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob)
	// 2 valid (have DetectorName); bad line + no-detector dropped.
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2", len(findings))
	}
	// Verified AWS → critical.
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("verified secret should be critical; got %q", findings[0].Severity)
	}
	if findings[0].CWE[0] != "CWE-798" {
		t.Errorf("CWE: %v", findings[0].CWE)
	}
	if findings[0].Endpoint != "/workspace/config.env:2" {
		t.Errorf("endpoint: %q", findings[0].Endpoint)
	}
	// Unverified Github → high.
	if findings[1].Severity != types.SeverityHigh {
		t.Errorf("unverified secret should be high; got %q", findings[1].Severity)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestSurface(t *testing.T) {
	th := New()
	if th.Name() != "trufflehog" || !th.SandboxExecution() {
		t.Error("surface wrong")
	}
}
