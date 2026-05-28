package subfinder

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseJSONL_Dedupes(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseJSONL(blob)
	// www.example.com appears twice; dedupe → 3 unique subdomains.
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3 (deduped)", len(findings))
	}
	gotHosts := map[string]bool{}
	for _, f := range findings {
		gotHosts[f.Endpoint] = true
	}
	for _, want := range []string{"www.example.com", "api.example.com", "cdn.example.com"} {
		if !gotHosts[want] {
			t.Errorf("missing host %q", want)
		}
	}
	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Severity: got %q, want info", findings[0].Severity)
	}
	if findings[0].RuleID != "subfinder::subdomain-found" {
		t.Errorf("RuleID: %q", findings[0].RuleID)
	}
}

func TestParseJSONL_EmptyBlob(t *testing.T) {
	if got := parseJSONL(nil); got != nil {
		t.Errorf("nil expected, got %v", got)
	}
}

func TestSubfinderTool_Surface(t *testing.T) {
	sf := New()
	if sf.Name() != "subfinder" {
		t.Errorf("Name: %q", sf.Name())
	}
	if !sf.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
}
