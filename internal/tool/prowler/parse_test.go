package prowler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseOCSF_OnlyFailures(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.ocsf.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parseOCSF(blob)
	// 2 FAIL + 1 PASS → only the 2 FAILs surface.
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2 (PASS excluded)", len(findings))
	}
	if findings[0].RuleID != "prowler::s3_bucket_public_access" {
		t.Errorf("RuleID[0]: %q", findings[0].RuleID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("severity[0]: %q", findings[0].Severity)
	}
	if findings[1].Severity != types.SeverityCritical {
		t.Errorf("severity[1]: %q, want critical", findings[1].Severity)
	}
	if findings[0].Endpoint == "" {
		t.Error("endpoint should carry the resource")
	}
}

func TestParseOCSF_EmptyAndNonArray(t *testing.T) {
	if parseOCSF(nil) != nil {
		t.Error("nil expected for empty")
	}
	if parseOCSF([]byte("{}")) != nil {
		t.Error("nil expected for non-array")
	}
}

func TestSurface(t *testing.T) {
	p := New()
	if p.Name() != "prowler" || !p.SandboxExecution() {
		t.Errorf("surface wrong")
	}
}
