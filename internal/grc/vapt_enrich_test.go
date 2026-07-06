package grc

import (
	"strings"
	"testing"
)

// TestRemediationForDiscoveryClasses asserts every CWE class the AI pentester actively
// discovers/proves has a SPECIFIC (non-generic) remediation + a real OWASP mapping in the VAPT
// deliverable — a proven finding must never fall through to the generic default.
func TestRemediationForDiscoveryClasses(t *testing.T) {
	generic := remediationFor([]string{"CWE-000-unknown"}, "web-investigate") // the default
	discovery := []string{"CWE-89", "CWE-78", "CWE-79", "CWE-943", "CWE-1336", "CWE-98", "CWE-601", "CWE-639", "CWE-269", "CWE-915", "CWE-287", "CWE-611", "CWE-94", "CWE-918", "CWE-22"}
	for _, cwe := range discovery {
		rem := remediationFor([]string{cwe}, "web-investigate")
		if rem == "" || rem == generic {
			t.Errorf("%s should have a specific remediation, got generic/empty: %q", cwe, rem)
		}
		ow := owaspFor([]string{cwe}, "web-investigate")
		if len(ow) == 0 || !strings.HasPrefix(ow[0], "A0") && !strings.HasPrefix(ow[0], "A1") {
			t.Errorf("%s should map to an OWASP Top 10 category, got %v", cwe, ow)
		}
	}
}
