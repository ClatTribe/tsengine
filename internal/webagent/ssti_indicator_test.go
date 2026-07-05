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

// TestSSTIProbeGuidance_MatchesDetector: the record_finding help must steer the agent to a MULTI-DIGIT
// SSTI probe whose product actually fires the ssti_eval detector. The canonical textbook probe {{7*7}}
// does NOT fire it — its 2-digit product (49) is too collision-prone to ground (sstiExprRe needs 2-7
// digit factors AND a >=4-digit product). Guidance that only said "a {{A*B}} probe" led an LLM straight
// to {{7*7}}, so it exploited SSTI but could never RECORD the finding (observed live on XBEN-009/025/076:
// flag captured, 0 findings recorded). This ties the guidance to the real detector so the two can't drift.
func TestSSTIProbeGuidance_MatchesDetector(t *testing.T) {
	var help string
	for _, td := range tools() {
		if td.name == "record_finding" {
			help = td.help
		}
	}
	if help == "" {
		t.Fatal("record_finding tool not found")
	}
	// The help must name the too-small canonical probe as the anti-pattern...
	if !strings.Contains(help, "{{7*7}}") {
		t.Errorf("record_finding help should name {{7*7}} as the anti-pattern (too small to ground): %s", help)
	}
	// ...and give the concrete multi-digit example it recommends...
	if !strings.Contains(help, "1234") {
		t.Errorf("record_finding help should give a concrete multi-digit example like {{1234*1234}}: %s", help)
	}
	// ...and that recommended probe must ACTUALLY fire the detector (guidance tied to code)...
	if !sstiEvaluated("{{1234*1234}}", "Hello 1522756!") {
		t.Error("the recommended multi-digit SSTI probe {{1234*1234}} must fire sstiEvaluated")
	}
	// ...while {{7*7}} must NOT (the very reason the multi-digit guidance is required).
	if sstiEvaluated("{{7*7}}", "Hello 49!") {
		t.Error("{{7*7}} must NOT fire sstiEvaluated — that collision-proneness is why multi-digit guidance exists")
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
