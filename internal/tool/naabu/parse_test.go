package naabu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_OpenPorts(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob)
	// 3 valid ports (22, 80, 443); bad lines + port:0 dropped.
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3", len(findings))
	}
	if findings[0].Endpoint != "93.184.216.34:22" {
		t.Errorf("endpoint[0]: %q", findings[0].Endpoint)
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("severity: %q", findings[0].Severity)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestSurface(t *testing.T) {
	n := New()
	if n.Name() != "naabu" || !n.SandboxExecution() {
		t.Error("surface wrong")
	}
}
