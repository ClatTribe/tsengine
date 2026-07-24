package trivy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestParseReport_AllThreeKinds(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := parseReport(blob)
	// 2 vulns + 1 misconfig + 1 secret = 4
	if len(findings) != 4 {
		t.Fatalf("got %d findings; want 4", len(findings))
	}

	// First two are vulns
	if findings[0].RuleID != "trivy::CVE-2021-42374" {
		t.Errorf("RuleID[0]: %q", findings[0].RuleID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("Severity[0]: %q", findings[0].Severity)
	}
	if len(findings[0].CWE) != 1 || findings[0].CWE[0] != "CWE-125" {
		t.Errorf("CWE[0]: %v", findings[0].CWE)
	}
	if findings[0].ToolArgs["pkg"] != "busybox" {
		t.Errorf("pkg projection lost: %v", findings[0].ToolArgs)
	}

	if findings[1].Severity != types.SeverityCritical {
		t.Errorf("Severity[1]: %q, want critical", findings[1].Severity)
	}

	// Misconfig
	if findings[2].RuleID != "trivy::misconfig::AVD-DS-0002" {
		t.Errorf("misconfig RuleID: %q", findings[2].RuleID)
	}
	if findings[2].Severity != types.SeverityHigh {
		t.Errorf("misconfig Severity: %q", findings[2].Severity)
	}

	// Secret
	if findings[3].RuleID != "trivy::secret::aws-access-key-id" {
		t.Errorf("secret RuleID: %q", findings[3].RuleID)
	}
	if findings[3].Severity != types.SeverityCritical {
		t.Errorf("secret Severity: %q", findings[3].Severity)
	}
	if findings[3].CWE[0] != "CWE-798" {
		t.Errorf("secret CWE: %v", findings[3].CWE)
	}
}

func TestParseReport_EmptyBlob(t *testing.T) {
	if got := parseReport(nil); got != nil {
		t.Errorf("nil expected, got %v", got)
	}
	if got := parseReport([]byte("")); got != nil {
		t.Errorf("nil expected for empty, got %v", got)
	}
}

func TestNormalizeSeverity_TrivyValues(t *testing.T) {
	cases := map[string]types.Severity{
		"CRITICAL": types.SeverityCritical,
		"HIGH":     types.SeverityHigh,
		"MEDIUM":   types.SeverityMedium,
		"LOW":      types.SeverityLow,
		"UNKNOWN":  types.SeverityInfo,
		"INFO":     types.SeverityInfo,
		"":         types.SeverityInfo,
		"weird":    types.SeverityInfo,
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestTrivyTool_Surface(t *testing.T) {
	tv := New()
	if tv.Name() != "trivy" {
		t.Errorf("Name: %q", tv.Name())
	}
	if !tv.SandboxExecution() {
		t.Error("SandboxExecution should be true")
	}
	if len(tv.MITRETechniques()) == 0 {
		t.Error("MITRETechniques empty")
	}
}

func TestVulnToFinding_CarriesClassAndFixState(t *testing.T) {
	// A distro OS package the distro won't fix → pkg_class os-pkgs + fix_state normalized to wont-fix.
	f := vulnToFinding(vulnerability{VulnerabilityID: "CVE-2023-1", PkgName: "libx", InstalledVersion: "1", Status: "will_not_fix", Severity: "HIGH"}, "img", "os-pkgs")
	if f.ToolArgs["pkg_class"] != "os-pkgs" {
		t.Errorf("pkg_class not carried: %q", f.ToolArgs["pkg_class"])
	}
	if f.ToolArgs["fix_state"] != "wont-fix" {
		t.Errorf("will_not_fix should normalize to wont-fix, got %q", f.ToolArgs["fix_state"])
	}
	// end_of_life also normalizes to wont-fix; affected passes through (fix may still land).
	if normalizeFixState("end_of_life") != "wont-fix" {
		t.Error("end_of_life should normalize to wont-fix")
	}
	if normalizeFixState("affected") != "affected" {
		t.Error("affected must pass through (still actionable)")
	}
}

func TestVulnToFinding_FixAvailability(t *testing.T) {
	f := vulnToFinding(vulnerability{VulnerabilityID: "CVE-1", PkgName: "p", FixedVersion: "2.0.0", Severity: "HIGH"}, "img", "lang-pkgs")
	if f.ToolArgs["fixable"] != "true" || !strings.Contains(f.Description, "upgrade to 2.0.0") {
		t.Errorf("fixable trivy wrong: args=%v desc=%q", f.ToolArgs, f.Description)
	}
	nf := vulnToFinding(vulnerability{VulnerabilityID: "CVE-2", PkgName: "p", FixedVersion: "", Severity: "HIGH"}, "img", "lang-pkgs")
	if nf.ToolArgs["fixable"] != "false" || !strings.Contains(nf.Description, "No fixed version available") {
		t.Errorf("no-fix trivy wrong: args=%v desc=%q", nf.ToolArgs, nf.Description)
	}
}
