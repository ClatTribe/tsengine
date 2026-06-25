package govulncheck

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
)

func TestRegistered(t *testing.T) {
	if _, ok := tool.Get("govulncheck"); !ok {
		t.Fatal("govulncheck not registered via init()")
	}
}

func TestKnownArgs(t *testing.T) {
	if got := New().KnownArgs(); len(got) != 1 || got[0] != "target" {
		t.Errorf("KnownArgs = %v, want [target]", got)
	}
}

func TestRun_MissingTarget(t *testing.T) {
	if _, err := New().Run(nil, tool.Args{}); err == nil {
		t.Error("expected error for missing target")
	}
}

// sample is a realistic govulncheck -json stream: two OSV definitions, then
// findings — GO-2023-CALLED is reachable (a trace frame names a function),
// GO-2023-IMPORTED is imported but never called (module/package-only trace,
// the FP class we drop).
const sample = `
{"osv":{"id":"GO-2023-CALLED","aliases":["CVE-2023-1111","GHSA-aaaa"],"summary":"Auth bypass in foo"}}
{"osv":{"id":"GO-2023-IMPORTED","aliases":["CVE-2023-2222"],"summary":"DoS in bar (unused)"}}
{"finding":{"osv":"GO-2023-IMPORTED","trace":[{"module":"example.com/bar","package":"example.com/bar"}]}}
{"finding":{"osv":"GO-2023-CALLED","trace":[{"module":"example.com/foo","package":"example.com/foo","function":"Verify"},{"module":"example.com/app","function":"main"}]}}
`

func TestParse_OnlyReachableReported(t *testing.T) {
	out := parse([]byte(sample))
	if len(out) != 1 {
		t.Fatalf("want exactly 1 finding (only the call-reachable vuln), got %d: %+v", len(out), out)
	}
	f := out[0]
	if f.RuleID != "govulncheck::CVE-2023-1111" {
		t.Errorf("rule_id = %q, want govulncheck::CVE-2023-1111 (CVE alias in rule_id for threat_intel)", f.RuleID)
	}
	if f.Tool != "govulncheck" || f.Severity != "high" {
		t.Errorf("tool/severity wrong: %+v", f)
	}
	if !strings.Contains(f.Title, "Call-reachable") || !strings.Contains(f.Title, "Auth bypass") {
		t.Errorf("title should mark reachability + summary: %q", f.Title)
	}
	if f.Endpoint != "example.com/foo" {
		t.Errorf("endpoint = %q, want the reachable package", f.Endpoint)
	}
}

func TestParse_GoIDWhenNoCVE(t *testing.T) {
	// A reachable vuln with no CVE alias keeps the GO id in the rule_id.
	blob := `{"osv":{"id":"GO-2024-9999","aliases":["GHSA-zzzz"],"summary":"x"}}
{"finding":{"osv":"GO-2024-9999","trace":[{"package":"p","function":"F"}]}}`
	out := parse([]byte(blob))
	if len(out) != 1 || out[0].RuleID != "govulncheck::GO-2024-9999" {
		t.Errorf("want govulncheck::GO-2024-9999, got %+v", out)
	}
}

func TestParse_Garbage(t *testing.T) {
	if out := parse([]byte("not json")); len(out) != 0 {
		t.Errorf("garbage should yield no findings, got %d", len(out))
	}
}
