package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestCrossToolMerge_CollapsesPayloadVariants pins the noise defect measured on WAVSEP.
//
// dalfox reports one finding per payload that worked, and the payload is in the URL — so every
// variant was a distinct endpoint, the exact-match key never collided, and nothing merged. Measured:
// 751 findings over 9 genuinely vulnerable cases (426 for one case), findings_enriched also 751,
// zero audit entries. The customer sees 751 XSS findings for 9 vulnerabilities.
func TestCrossToolMerge_CollapsesPayloadVariants(t *testing.T) {
	base := "http://h/app/case.jsp?userinput="
	in := []types.Finding{
		{ID: "1", Tool: "dalfox", RuleID: "dalfox::verified-xss", Endpoint: base + "%3Cscript%3E"},
		{ID: "2", Tool: "dalfox", RuleID: "dalfox::verified-xss", Endpoint: base + "%22onload%3D"},
		{ID: "3", Tool: "dalfox", RuleID: "dalfox::verified-xss", Endpoint: base + "%3Csvg%2Fonload"},
	}
	out, audit := (&CrossToolMerge{}).Finalize(in)
	if len(out) != 1 {
		t.Errorf("3 payloads against the same parameter are ONE vulnerability, got %d findings", len(out))
	}
	if len(audit) != 2 {
		t.Errorf("each collapsed variant must be recorded, got %d audit entries", len(audit))
	}
}

// A different PARAMETER on the same page is a different vulnerability and must survive — dropping
// values must not become dropping the whole query.
func TestCrossToolMerge_KeepsDistinctParameters(t *testing.T) {
	in := []types.Finding{
		{ID: "1", Tool: "dalfox", RuleID: "r", Endpoint: "http://h/app/p.jsp?a=%3Cscript%3E"},
		{ID: "2", Tool: "dalfox", RuleID: "r", Endpoint: "http://h/app/p.jsp?b=%3Cscript%3E"},
	}
	if out, _ := (&CrossToolMerge{}).Finalize(in); len(out) != 2 {
		t.Errorf("?a= and ?b= being injectable are two vulnerabilities, got %d", len(out))
	}
}

// Different rule_ids describe different weaknesses and must not be collapsed together.
func TestCrossToolMerge_KeepsDistinctRules(t *testing.T) {
	in := []types.Finding{
		{ID: "1", Tool: "dalfox", RuleID: "dalfox::verified-xss", Endpoint: "http://h/p.jsp?q=1"},
		{ID: "2", Tool: "dalfox", RuleID: "dalfox::reflected-xss", Endpoint: "http://h/p.jsp?q=2"},
	}
	if out, _ := (&CrossToolMerge{}).Finalize(in); len(out) != 2 {
		t.Errorf("distinct rule_ids are distinct findings, got %d", len(out))
	}
}

// An endpoint with no query string is untouched — repo findings are file:line, not URLs.
func TestCrossToolMerge_LeavesNonQueryEndpointsAlone(t *testing.T) {
	in := []types.Finding{
		{ID: "1", Tool: "semgrep", RuleID: "r", Endpoint: "src/A.java:42"},
		{ID: "2", Tool: "semgrep", RuleID: "r", Endpoint: "src/A.java:99"},
	}
	if out, _ := (&CrossToolMerge{}).Finalize(in); len(out) != 2 {
		t.Errorf("different lines in a file are different findings, got %d", len(out))
	}
}
