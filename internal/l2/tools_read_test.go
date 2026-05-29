package l2

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func sampleFindings() []types.Finding {
	return []types.Finding{
		{ID: "f-001", RuleID: "sqlmap::sqli", Tool: "sqlmap", Severity: types.SeverityCritical,
			CWE: []string{"CWE-89"}, Endpoint: "https://x/p?id=1", Title: "SQL injection",
			Description: "boolean-based blind", ThreatIntel: &types.ThreatIntel{}},
		{ID: "f-002", RuleID: "nuclei::xss", Tool: "nuclei", Severity: types.SeverityMedium,
			CWE: []string{"CWE-79"}, Endpoint: "https://x/s?q=1", Title: "Reflected XSS"},
	}
}

func TestBuildCatalog_UnderCapAndHasGetFinding(t *testing.T) {
	c := BuildCatalog(Deps{Target: webTarget(), L1Findings: sampleFindings()})
	if err := c.Validate(); err != nil {
		t.Fatalf("catalog must satisfy the ≤12 cap: %v", err)
	}
	if _, ok := c.find("get_finding"); !ok {
		t.Error("catalog should include get_finding")
	}
	// Core tools still present.
	if _, ok := c.find("finish_scan"); !ok {
		t.Error("catalog should include finish_scan")
	}
}

func TestGetFinding_ReturnsFullDetailById(t *testing.T) {
	c := BuildCatalog(Deps{L1Findings: sampleFindings()})
	gf, _ := c.find("get_finding")

	res, err := gf.Handler(context.Background(), map[string]any{"id": "f-001"}, &State{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.Err {
		t.Fatalf("unexpected error result: %s", res.Content)
	}
	// Full detail (not just the digest): description + CWE present.
	for _, want := range []string{"f-001", "CWE-89", "boolean-based blind", "sqlmap::sqli"} {
		if !strings.Contains(res.Content, want) {
			t.Errorf("get_finding detail missing %q in:\n%s", want, res.Content)
		}
	}
}

func TestGetFinding_UnknownId(t *testing.T) {
	c := BuildCatalog(Deps{L1Findings: sampleFindings()})
	gf, _ := c.find("get_finding")
	res, _ := gf.Handler(context.Background(), map[string]any{"id": "f-999"}, &State{})
	if !res.Err {
		t.Error("unknown id should return an error result")
	}
}

func TestRenderFinding_ElidesRawOutput(t *testing.T) {
	f := sampleFindings()[0]
	f.RawOutput = []byte(`{"huge":"` + strings.Repeat("x", 5000) + `"}`)
	out := renderFinding(f)
	if strings.Contains(out, "xxxxxxxxxx") {
		t.Error("raw_output should be elided from get_finding detail")
	}
	if !strings.Contains(out, "f-001") {
		t.Error("core fields should remain")
	}
}
