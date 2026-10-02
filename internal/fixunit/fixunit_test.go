package fixunit

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// A scanner-declared fix unit is believed over our own derivation, and findings without one keep the
// existing grouping exactly.
func TestKey_ScannerDeclaredUnitOutranksDerivation(t *testing.T) {
	declared := types.Finding{RuleID: "nessus::1::CVE-2021-44228",
		ToolArgs: map[string]string{ToolArgFixUnit: "nessus-plugin:1", "pkg": "log4j", "installed_version": "2.14"}}
	if got := Key(declared); got != "unit:nessus-plugin:1" {
		t.Errorf("Key = %q, want the scanner's unit", got)
	}
	pkg := types.Finding{RuleID: "grype::CVE-1", ToolArgs: map[string]string{"pkg": "log4j", "installed_version": "2.14"}}
	if got := Key(pkg); got != "pkg:log4j@2.14" {
		t.Errorf("Key = %q, want the package coordinate unchanged", got)
	}
	if got := Key(types.Finding{RuleID: "semgrep::x"}); got != "rule:semgrep::x" {
		t.Errorf("Key = %q, want the rule id unchanged", got)
	}
}
