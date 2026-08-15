package importers

import (
	"testing"
	"time"
)

// A tool that namespaces its own rule ids must not get them doubled.
//
// This is not cosmetic. Rule ids are matched by PREFIX throughout the product — exclusion rules,
// ignore rules, the readiness checklist's gap matching, the access review's identity rules — so
// "operate::operate::stale-account" is stored, displayed, and participates in NONE of them.
//
// Found by driving the access review against an imported SARIF: the findings landed and the review
// stayed empty.
func TestNamespacedRule_DoesNotDoublePrefix(t *testing.T) {
	cases := []struct{ tool, rule, want string }{
		{"operate", "operate::stale-account", "operate::stale-account"}, // already namespaced
		{"semgrep", "semgrep.rules.sqli", "semgrep.rules.sqli"},         // dot-namespaced
		{"trivy", "CVE-2026-1234", "trivy::CVE-2026-1234"},              // bare — prefix it
		{"", "some-rule", "some-rule"},                                  // no tool to prefix with
		{"gitleaks", "", "gitleaks"},                                    // no rule at all
	}
	for _, c := range cases {
		if got := namespacedRule(c.tool, c.rule); got != c.want {
			t.Errorf("namespacedRule(%q, %q) = %q, want %q", c.tool, c.rule, got, c.want)
		}
	}
}

// End to end through the parser, since that is where the bug actually bit.
func TestFromSARIF_KeepsAToolsOwnNamespace(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"operate"}},"results":[
	  {"ruleId":"operate::stale-account","level":"error","message":{"text":"Stale active account: a@b.io"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a@b.io"}}}]}]}]}`
	scan, err := FromSARIF([]byte(doc), "acme", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.FindingsRaw) != 1 {
		t.Fatalf("got %d findings", len(scan.FindingsRaw))
	}
	if got := scan.FindingsRaw[0].RuleID; got != "operate::stale-account" {
		t.Errorf("rule id = %q — a double prefix makes this finding invisible to every "+
			"prefix-matching feature in the product", got)
	}
}
