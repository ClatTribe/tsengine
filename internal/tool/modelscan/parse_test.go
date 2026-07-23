package modelscan

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// a real-shaped modelscan JSON report: a poisoned pickle that would run os.system on load — the
// incident's code-execution-on-load vector.
const sampleReport = `{
  "summary": {"total_issues": 2, "input_path": "/workspace/model.pkl"},
  "issues": [
    {"description": "Use of unsafe operator 'system' from module 'posix'",
     "operator": "posix.system", "module": "posix", "source": "/workspace/model.pkl",
     "scanner": "modelscan.scanners.PickleUnsafeOpScan", "severity": "CRITICAL"},
    {"description": "Use of unsafe operator 'eval' from module 'builtins'",
     "operator": "builtins.eval", "module": "builtins", "source": "/workspace/data/loader.pkl",
     "scanner": "modelscan.scanners.PickleUnsafeOpScan", "severity": "HIGH"}
  ],
  "errors": []
}`

func TestParse_PoisonedArtifact(t *testing.T) {
	fs := parse([]byte(sampleReport), "/workspace")
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	f := fs[0]
	if f.Tool != "modelscan" || f.Severity != types.SeverityCritical {
		t.Errorf("first finding wrong: %+v", f)
	}
	if f.RuleID != "modelscan::unsafe-op::posix.system" {
		t.Errorf("rule id wrong: %q", f.RuleID)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-502" {
		t.Errorf("unsafe deserialization must be CWE-502, got %v", f.CWE)
	}
	if f.Endpoint != "/workspace/model.pkl" {
		t.Errorf("endpoint should be the artifact path, got %q", f.Endpoint)
	}
	if !strings.Contains(f.Description, "execute code") {
		t.Errorf("description should explain the code-execution risk, got %q", f.Description)
	}
	if fs[1].Severity != types.SeverityHigh {
		t.Errorf("second finding should be HIGH, got %s", fs[1].Severity)
	}
}

func TestParse_CleanAndMalformed(t *testing.T) {
	// a clean scan → no findings (grounded: a safetensors model yields nothing)
	if fs := parse([]byte(`{"summary":{"total_issues":0},"issues":[],"errors":[]}`), "/x"); fs != nil {
		t.Errorf("a clean artifact must yield no findings, got %v", fs)
	}
	// non-JSON / empty → no findings, never a crash
	for _, b := range []string{"", "not json", "[]", "   "} {
		if fs := parse([]byte(b), "/x"); fs != nil {
			t.Errorf("input %q must yield no findings", b)
		}
	}
}

// TestSeverityMap: an unknown/blank severity is HIGH — an unsafe operator is never downgraded to info.
func TestSeverityMap(t *testing.T) {
	cases := map[string]types.Severity{
		"CRITICAL": types.SeverityCritical, "high": types.SeverityHigh,
		"Medium": types.SeverityMedium, "LOW": types.SeverityLow,
		"": types.SeverityHigh, "weird": types.SeverityHigh,
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestRun_RequiresTarget: no target is a loud error, not a silent no-op.
func TestRun_RequiresTarget(t *testing.T) {
	if _, err := New().Run(context.Background(), tool.Args{}); err == nil {
		t.Error("missing target must error")
	}
}

// TestRegistered: the tool must be in the registry (so a handler can dispatch it) + arg contract.
func TestRegistered(t *testing.T) {
	tl, ok := tool.Get("modelscan")
	if !ok {
		t.Fatal("modelscan must self-register via init()")
	}
	if !tool.ArgIsKnown(tl, "target") {
		t.Error("target must be a known arg")
	}
	if tool.ArgIsKnown(tl, "not-a-real-arg") {
		t.Error("an unknown arg must be rejected by the contract")
	}
}
