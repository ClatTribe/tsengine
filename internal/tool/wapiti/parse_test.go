package wapiti

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// a real-shaped wapiti JSON report: an SQLi and a reflected XSS.
const sample = `{
  "vulnerabilities": {
    "SQL Injection": [
      {"method":"GET","path":"http://t/search","info":"SQL Injection via q","level":3,"parameter":"q","module":"sql"}
    ],
    "Cross Site Scripting": [
      {"method":"GET","path":"http://t/hello","info":"XSS via name","level":2,"parameter":"name","module":"xss"}
    ],
    "Secure Flag cookie": [
      {"method":"GET","path":"http://t/","info":"session cookie without Secure flag","level":1,"parameter":"","module":"cookieflags"}
    ]
  }
}`

func find(fs []types.SandboxEmittedFinding, rule string) *types.SandboxEmittedFinding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestParse_MapsCategoriesToCWEAndSeverity(t *testing.T) {
	fs := parse([]byte(sample), "http://t")
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}
	sqli := find(fs, "wapiti::sql-injection")
	if sqli == nil || len(sqli.CWE) != 1 || sqli.CWE[0] != "CWE-89" {
		t.Errorf("SQLi must map to CWE-89: %+v", sqli)
	}
	if sqli.Severity != types.SeverityHigh {
		t.Errorf("SQLi (level 3, serious class) must be high, got %s", sqli.Severity)
	}
	if !strings.Contains(sqli.Endpoint, "param: q") {
		t.Errorf("endpoint should carry the injected parameter: %q", sqli.Endpoint)
	}
	// XSS at level 2 is a serious class → floored to high (not medium).
	xss := find(fs, "wapiti::cross-site-scripting")
	if xss == nil || xss.Severity != types.SeverityHigh {
		t.Errorf("XSS is a serious class, floored to high: %+v", xss)
	}
	// a cookie-flag finding at level 1 stays low (not a serious injection class).
	cookie := find(fs, "wapiti::secure-flag-cookie")
	if cookie == nil || cookie.Severity != types.SeverityLow {
		t.Errorf("cookie-flag finding should be low: %+v", cookie)
	}
	if cookie.CWE[0] != "CWE-614" {
		t.Errorf("Secure-flag cookie must map to CWE-614: %v", cookie.CWE)
	}
}

func TestParse_CleanAndMalformed(t *testing.T) {
	if fs := parse([]byte(`{"vulnerabilities":{}}`), "/x"); fs != nil {
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
	tl, ok := tool.Get("wapiti")
	if !ok {
		t.Fatal("wapiti must self-register via init()")
	}
	if !tool.ArgIsKnown(tl, "target") {
		t.Error("target must be a known arg")
	}
	if tool.ArgIsKnown(tl, "not-a-real-arg") {
		t.Error("an unknown arg must be rejected by the contract")
	}
}
