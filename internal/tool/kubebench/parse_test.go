package kubebench

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// a real-shaped kube-bench JSON report: a scored FAIL, an unscored FAIL, a WARN, and a PASS.
const sample = `{
  "Controls": [
    {"id":"1","text":"Master Node Security Configuration","tests":[
      {"section":"1.2","results":[
        {"test_number":"1.2.6","test_desc":"Ensure that the --kubelet-certificate-authority argument is set","status":"FAIL","scored":true,"remediation":"Edit the API server pod spec"},
        {"test_number":"1.2.16","test_desc":"Ensure that the admission control plugin PodSecurityPolicy is set","status":"FAIL","scored":false,"remediation":"Follow the docs"},
        {"test_number":"1.2.35","test_desc":"Ensure that the --encryption-provider-config argument is set","status":"WARN","scored":false,"remediation":"Enable encryption at rest"},
        {"test_number":"1.2.1","test_desc":"Ensure anonymous-auth is false","status":"PASS","scored":true}
      ]}
    ]}
  ],
  "Totals": {"total_fail":2,"total_warn":1,"total_pass":1}
}`

func find(fs []types.SandboxEmittedFinding, rule string) *types.SandboxEmittedFinding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestParse_EmitsFailAndWarnNotPass(t *testing.T) {
	fs := parse([]byte(sample))
	if len(fs) != 3 { // 2 FAIL + 1 WARN; the PASS is dropped
		t.Fatalf("want 3 findings (FAIL+WARN, not PASS), got %d", len(fs))
	}
	scored := find(fs, "kube-bench::1.2.6")
	if scored == nil || scored.Severity != types.SeverityHigh {
		t.Errorf("a scored FAIL must be high: %+v", scored)
	}
	if scored.Endpoint != "CIS 1.2.6" {
		t.Errorf("endpoint should be the CIS control, got %q", scored.Endpoint)
	}
	unscored := find(fs, "kube-bench::1.2.16")
	if unscored == nil || unscored.Severity != types.SeverityMedium {
		t.Errorf("an unscored FAIL must be medium: %+v", unscored)
	}
	warn := find(fs, "kube-bench::1.2.35")
	if warn == nil || warn.Severity != types.SeverityLow {
		t.Errorf("a WARN must be low: %+v", warn)
	}
	if find(fs, "kube-bench::1.2.1") != nil {
		t.Error("a PASS must NOT produce a finding")
	}
}

func TestParse_CleanAndMalformed(t *testing.T) {
	if fs := parse([]byte(`{"Controls":[]}`)); fs != nil {
		t.Errorf("a clean audit must yield no findings, got %v", fs)
	}
	for _, b := range []string{"", "not json", "[]", "   "} {
		if fs := parse([]byte(b)); fs != nil {
			t.Errorf("input %q must yield no findings", b)
		}
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := tool.Get("kube-bench"); !ok {
		t.Fatal("kube-bench must self-register via init()")
	}
}
