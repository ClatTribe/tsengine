package syft

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestSummarize_ComponentCount(t *testing.T) {
	blob := []byte(`{"components":[{"name":"openssl","version":"3.0"},{"name":"zlib","version":"1.2"}]}`)
	out := summarize(blob, "nginx:1.14")
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1 SBOM summary", len(out))
	}
	if out[0].Severity != types.SeverityInfo || out[0].RuleID != "syft::sbom-generated" {
		t.Errorf("finding = %+v", out[0])
	}
	if !strings.Contains(out[0].Title, "2 components") {
		t.Errorf("title = %q, want component count", out[0].Title)
	}
	if out[0].ToolArgs["component_count"] != "2" {
		t.Errorf("component_count = %q", out[0].ToolArgs["component_count"])
	}
}

func TestSummarize_EmptyNoFinding(t *testing.T) {
	if summarize([]byte(`{"components":[]}`), "x") != nil {
		t.Error("empty SBOM should yield no finding")
	}
	if summarize(nil, "x") != nil {
		t.Error("nil should yield no finding")
	}
}

func TestSyft_Identity(t *testing.T) {
	if _, ok := tool.Get("syft"); !ok {
		t.Error("syft not registered")
	}
}
