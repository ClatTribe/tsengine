package nikto

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A representative Nikto JSON run (single-host shape): a clickjacking header gap (low, CWE-1021), a
// server-version disclosure (low, CWE-200), and a dangerous default-admin path (bumped to medium).
const fixture = `{
  "host": "example.com",
  "port": "443",
  "vulnerabilities": [
    {"id": "999957", "method": "GET", "url": "/", "msg": "The anti-clickjacking X-Frame-Options header is not present."},
    {"id": "999103", "method": "GET", "url": "/", "msg": "The server banner version may be outdated."},
    {"id": "000123", "method": "GET", "url": "/phpmyadmin/", "msg": "phpMyAdmin default admin interface found - remote access possible."}
  ]
}`

func TestParse_MapsVulnsWithSeverityAndCWE(t *testing.T) {
	out := parse([]byte(fixture))
	if len(out) != 3 {
		t.Fatalf("want 3 findings, got %d: %+v", len(out), out)
	}
	byEndpoint := map[string]types.SandboxEmittedFinding{}
	for _, f := range out {
		if f.Tool != "nikto" || f.Title == "" {
			t.Errorf("finding missing core fields: %+v", f)
		}
		byEndpoint[f.Endpoint] = f
	}
	// clickjacking → low + CWE-1021
	cj := byEndpoint["/"]
	if cj.Severity != types.SeverityLow {
		t.Errorf("a header gap should be low, got %s", cj.Severity)
	}
	// the phpMyAdmin/admin/remote finding bumps to medium
	admin := byEndpoint["/phpmyadmin/"]
	if admin.Severity != types.SeverityMedium {
		t.Errorf("a dangerous default-admin path should bump to medium, got %s", admin.Severity)
	}
	// at least one finding carries a mapped CWE
	var anyCWE bool
	for _, f := range out {
		if len(f.CWE) > 0 {
			anyCWE = true
		}
	}
	if !anyCWE {
		t.Error("the header/disclosure findings should carry a mapped CWE")
	}
}

// The array-of-hosts shape (some Nikto versions) is also handled; malformed → empty, no panic.
func TestParse_ArrayShapeAndMalformed(t *testing.T) {
	arr := `[{"host":"a.com","vulnerabilities":[{"id":"1","url":"/x","msg":"thing found"}]}]`
	if got := parse([]byte(arr)); len(got) != 1 || got[0].Endpoint != "/x" {
		t.Errorf("array-of-hosts shape should parse, got %+v", got)
	}
	if got := parse([]byte("not json")); got != nil {
		t.Errorf("malformed → no findings, got %+v", got)
	}
}
