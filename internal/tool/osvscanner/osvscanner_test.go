package osvscanner

import (
	"strings"
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

func TestParse_FixAvailability(t *testing.T) {
	// A vuln with a `fixed` event → fixable + fixed_version + a "Fix available" note.
	blob := []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[
	  {"package":{"name":"golang.org/x/net","version":"0.1.0","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"CVE-2023-1","summary":"bad","affected":[
	     {"package":{"name":"golang.org/x/net"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"0.7.0"}]}]}]}]}]}]}`)
	fs := parse(blob)
	if len(fs) != 1 {
		t.Fatalf("got %d", len(fs))
	}
	if fs[0].ToolArgs["fixable"] != "true" || fs[0].ToolArgs["fixed_version"] != "0.7.0" {
		t.Errorf("fixable/fixed_version wrong: %v", fs[0].ToolArgs)
	}
	if !strings.Contains(fs[0].Description, "upgrade to 0.7.0") {
		t.Errorf("fix note missing: %q", fs[0].Description)
	}

	// No `fixed` event → not fixable + a mitigate note.
	blob2 := []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[
	  {"package":{"name":"p","version":"1.0","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"CVE-2023-2","summary":"bad","affected":[
	     {"package":{"name":"p"},"ranges":[{"events":[{"introduced":"0"}]}]}]}]}]}]}`)
	fs2 := parse(blob2)
	if fs2[0].ToolArgs["fixable"] != "false" {
		t.Errorf("no-fix should be fixable=false, got %q", fs2[0].ToolArgs["fixable"])
	}
	if !strings.Contains(fs2[0].Description, "No fixed version available") {
		t.Errorf("no-fix note missing: %q", fs2[0].Description)
	}
}
