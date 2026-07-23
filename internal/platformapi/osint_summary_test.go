package platformapi

import "testing"

// TestOSINTSummaryOrder_CoversEveryLabel guards the bug this fixed: a class present in osintClassLabel
// but MISSING from the ordered display list gets no summary tile (its findings flow to issues but vanish
// from the /osint overview). Every label must be in the order list.
func TestOSINTSummaryOrder_CoversEveryLabel(t *testing.T) {
	inOrder := map[string]bool{}
	for _, l := range osintSummaryOrder {
		inOrder[l] = true
	}
	for rule, label := range osintClassLabel {
		if !inOrder[label] {
			t.Errorf("class %q → label %q is not in osintSummaryOrder, so it would render no summary tile", rule, label)
		}
	}
	// the newly-wired live classes must be represented
	for _, rule := range []string{"osint::stealer-log", "osint::subdomain-takeover", "osint::cert-unexpected-issuer"} {
		if osintClassLabel[rule] == "" {
			t.Errorf("%s must have a summary label", rule)
		}
	}
}
