package osvscanner

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestParse_PrefersCVEInRuleID(t *testing.T) {
	blob := []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[
	  {"package":{"name":"golang.org/x/net","version":"0.1.0","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"GHSA-xxxx","summary":"bad","aliases":["CVE-2023-1111","GHSA-xxxx"]}]},
	  {"package":{"name":"left-pad","version":"1.0.0","ecosystem":"npm"},
	   "vulnerabilities":[{"id":"OSV-2020-1","summary":"nope","aliases":[]}]}
	]}]}`)
	out := parse(blob)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	// CVE alias preferred → RuleID carries the CVE so the corroborator joins
	// it with trivy/grype.
	if out[0].RuleID != "osv-scanner::CVE-2023-1111" {
		t.Errorf("RuleID[0] = %q, want osv-scanner::CVE-2023-1111", out[0].RuleID)
	}
	if out[0].Endpoint != "golang.org/x/net@0.1.0" {
		t.Errorf("endpoint[0] = %q", out[0].Endpoint)
	}
	// No CVE alias → native OSV id retained.
	if out[1].RuleID != "osv-scanner::OSV-2020-1" {
		t.Errorf("RuleID[1] = %q, want native OSV id", out[1].RuleID)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil) != nil {
		t.Error("nil expected")
	}
}

func TestOSV_Identity(t *testing.T) {
	if _, ok := tool.Get("osv-scanner"); !ok {
		t.Error("osv-scanner not registered")
	}
}
