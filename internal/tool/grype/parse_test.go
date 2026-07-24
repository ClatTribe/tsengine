package grype

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParse_Matches(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	findings := parse(blob, "nginx:1.14")
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3", len(findings))
	}
	if findings[0].RuleID != "grype::CVE-2021-44228" {
		t.Errorf("RuleID[0]: %q", findings[0].RuleID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("severity[0]: %q", findings[0].Severity)
	}
	// Negligible → info.
	if findings[2].Severity != types.SeverityInfo {
		t.Errorf("severity[2]: %q, want info", findings[2].Severity)
	}
	// Endpoint scopes to the package (so cross_tool_merge keeps distinct).
	if !strings.Contains(findings[0].Endpoint, "log4j-core@2.14.1") {
		t.Errorf("endpoint should carry package: %q", findings[0].Endpoint)
	}
}

func TestParse_Empty(t *testing.T) {
	if parse(nil, "x") != nil {
		t.Error("nil expected")
	}
}

func TestParse_CarriesPkgTypeAndFixState(t *testing.T) {
	blob := []byte(`{"matches":[{"vulnerability":{"id":"CVE-2023-0001","severity":"High","fix":{"state":"wont-fix","versions":[]}},"artifact":{"name":"libfoo","version":"1.0","type":"deb"}}]}`)
	fs := parse(blob, "debian:11")
	if len(fs) != 1 {
		t.Fatalf("got %d", len(fs))
	}
	if fs[0].ToolArgs["pkg_type"] != "deb" {
		t.Errorf("pkg_type not carried: %q", fs[0].ToolArgs["pkg_type"])
	}
	if fs[0].ToolArgs["fix_state"] != "wont-fix" {
		t.Errorf("fix_state not carried: %q", fs[0].ToolArgs["fix_state"])
	}
}

func TestSurface(t *testing.T) {
	g := New()
	if g.Name() != "grype" || !g.SandboxExecution() {
		t.Error("surface wrong")
	}
}

func TestParse_FixAvailability(t *testing.T) {
	// fixed → fixable + version + "Fix available" note.
	fx := parse([]byte(`{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High","fix":{"state":"fixed","versions":["1.2.3"]}},"artifact":{"name":"p","version":"1.0","type":"npm"}}]}`), "img")
	if fx[0].ToolArgs["fixable"] != "true" || fx[0].ToolArgs["fixed_version"] != "1.2.3" {
		t.Errorf("fixable/fixed_version wrong: %v", fx[0].ToolArgs)
	}
	if !strings.Contains(fx[0].Description, "Fix available: upgrade to 1.2.3") {
		t.Errorf("fix note missing: %q", fx[0].Description)
	}
	// no fix → fixable false + "No fixed version" note.
	nf := parse([]byte(`{"matches":[{"vulnerability":{"id":"CVE-2","severity":"High","fix":{"state":"not-fixed","versions":[]}},"artifact":{"name":"p","version":"1.0","type":"npm"}}]}`), "img")
	if nf[0].ToolArgs["fixable"] != "false" {
		t.Errorf("no-fix should be fixable=false, got %q", nf[0].ToolArgs["fixable"])
	}
	if !strings.Contains(nf[0].Description, "No fixed version available") {
		t.Errorf("no-fix note missing: %q", nf[0].Description)
	}
}
