package httpx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_Probes(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob)
	// 2 valid (have url); garbage + no-url dropped.
	if len(findings) != 2 {
		t.Fatalf("got %d findings; want 2", len(findings))
	}
	if findings[0].Endpoint != "https://example.com" {
		t.Errorf("endpoint[0]: %q", findings[0].Endpoint)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("severity: %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "200") || !strings.Contains(findings[0].Title, "ECS") {
		t.Errorf("title should carry status + webserver: %q", findings[0].Title)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestSurface(t *testing.T) {
	h := New()
	if h.Name() != "httpx" || !h.SandboxExecution() {
		t.Error("surface wrong")
	}
}
