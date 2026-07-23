package brakeman

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// a real-shaped brakeman JSON report: a high-confidence SQL injection + a weak mass-assignment.
const sample = `{
  "scan_info": {"app_path": "/workspace"},
  "warnings": [
    {"warning_type":"SQL Injection","message":"Possible SQL injection","file":"app/models/user.rb","line":42,"confidence":"High","cwe_id":[89],"code":"User.where(\"name = '#{params[:n]}'\")"},
    {"warning_type":"Mass Assignment","message":"Unprotected attribute","file":"app/controllers/users_controller.rb","line":10,"confidence":"Weak","cwe_id":[915]}
  ],
  "errors": []
}`

func find(fs []types.SandboxEmittedFinding, rule string) *types.SandboxEmittedFinding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestParse_UsesBrakemanCWEAndConfidence(t *testing.T) {
	fs := parse([]byte(sample), "/workspace")
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	sqli := find(fs, "brakeman::sql-injection")
	if sqli == nil {
		t.Fatal("missing SQL Injection finding")
	}
	if len(sqli.CWE) != 1 || sqli.CWE[0] != "CWE-89" {
		t.Errorf("CWE must come from brakeman's cwe_id (89), got %v", sqli.CWE)
	}
	if sqli.Severity != types.SeverityHigh {
		t.Errorf("High confidence → high severity, got %s", sqli.Severity)
	}
	if sqli.Endpoint != "app/models/user.rb:42" {
		t.Errorf("endpoint should be file:line, got %q", sqli.Endpoint)
	}
	ma := find(fs, "brakeman::mass-assignment")
	if ma == nil || ma.Severity != types.SeverityLow {
		t.Errorf("Weak confidence → low severity: %+v", ma)
	}
	if ma.CWE[0] != "CWE-915" {
		t.Errorf("mass-assignment CWE should be 915, got %v", ma.CWE)
	}
}

func TestParse_CleanAndMalformed(t *testing.T) {
	if fs := parse([]byte(`{"warnings":[]}`), "/x"); fs != nil {
		t.Errorf("a clean scan must yield no findings, got %v", fs)
	}
	for _, b := range []string{"", "not json", "[]", "   "} {
		if fs := parse([]byte(b), "/x"); fs != nil {
			t.Errorf("input %q must yield no findings", b)
		}
	}
}

func TestRun_RequiresTarget(t *testing.T) {
	if _, err := New().Run(context.Background(), tool.Args{}); err == nil {
		t.Error("missing target must error")
	}
}

func TestRegistered(t *testing.T) {
	tl, ok := tool.Get("brakeman")
	if !ok {
		t.Fatal("brakeman must self-register via init()")
	}
	if !tool.ArgIsKnown(tl, "target") {
		t.Error("target must be a known arg")
	}
}
