package webagent

import (
	"strings"
	"testing"
)

// TestSSTIEvalIndicator: a template-injection arithmetic probe whose PRODUCT appears in the response
// (and whose literal expression does NOT) is a deterministic SSTI signal — the engine evaluated it.
// A mere reflection (literal echoed back) must NOT fire it (no false positive).
func TestSSTIEvalIndicator(t *testing.T) {
	cases := []struct {
		name, payload, body string
		want                bool
	}{
		{"jinja eval", "{{1337*1337}}", "<p>Hello 1787569!</p>", true},
		{"dollar eval", "${999*999}", "result: 998001", true},
		{"erb eval", "<%= 4242*4242 %>", "x=17994564 y", true},
		{"ruby-hash eval", "#{1234*1234}", "1522756", true},
		{"reflected literal (NOT eval)", "{{1337*1337}}", "you said {{1337*1337}}", false},
		{"product absent (NOT eval)", "{{1337*1337}}", "nothing here", false},
		{"tiny product too collision-prone", "{{7*7}}", "49 items", false},
		{"no ssti payload", "hello", "hello 42", false},
	}
	for _, c := range cases {
		got := sstiEvaluated(c.payload, c.body)
		if got != c.want {
			t.Errorf("%s: sstiEvaluated(%q, %q) = %v, want %v", c.name, c.payload, c.body, got, c.want)
		}
	}
}

// TestRecordFinding_SSTI: an SSTI finding grounded by an ssti_eval turn must be RECORDABLE (it was
// silently rejected as an "unknown vuln class" before — the agent could exploit SSTI but not report it).
func TestRecordFinding_SSTI(t *testing.T) {
	cc := &Context{}
	cc.turnN = 1
	cc.History = []Turn{{ID: "t-001", Indicators: []string{"ssti_eval"}}}
	out := tRecord(cc, map[string]any{
		"route": "/?name=", "class": "ssti", "evidence": []any{"t-001"},
		"severity": "high", "rationale": "template injection RCE",
	})
	if strings.Contains(out, "REJECTED") {
		t.Fatalf("SSTI finding rejected: %s", out)
	}
	if len(cc.Findings) != 1 || cc.Findings[0].Class != "ssti" {
		t.Fatalf("SSTI finding not recorded: %+v", cc.Findings)
	}
}
