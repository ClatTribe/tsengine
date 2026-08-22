package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE reason this renderer uses html/template. A VAPT report carries attacker-controlled text by
// construction: finding titles and endpoints come from scanner output, and a reflected-XSS PoC is
// LITERALLY a script payload. Rendered unescaped, the vulnerability report would execute the
// payload it is reporting, in the browser of the customer/auditor who opened it.
func TestRenderVAPTHTML_EscapesAttackerControlledContent(t *testing.T) {
	payload := `<script>alert(document.domain)</script>`
	f := []types.Finding{{
		ID: "f-1", RuleID: `nuclei::xss"><img src=x onerror=alert(1)>`, Tool: "nuclei",
		Severity: types.SeverityHigh, CWE: []string{"CWE-79"},
		Title:              `Reflected XSS via ` + payload,
		Endpoint:           `https://acme.example/q?s=` + payload,
		Description:        `The parameter reflects ` + payload + ` unencoded.`,
		VerificationStatus: "verified",
	}}
	// The captured PoC is the most dangerous field of all — it is the working exploit.
	f[0].Description += "\n[Exploitation PoC — reflected] sent " + payload + " and it executed."

	html := RenderVAPTHTML(ReportFromFindings(f, []string{"https://acme.example"}, "Acme", time.Now().UTC(), nil))

	// The property is that no attacker string can FORM MARKUP: the tag-opening "<" and the
	// attribute-breaking quote must be escaped. The inert words ("onerror=alert(1)" as text) are
	// expected to survive — the reader has to be able to see the payload that was used.
	if strings.Contains(html, "<script>alert") || strings.Contains(html, "<img src=x") {
		t.Fatal("attacker payload formed real markup — the deliverable is an XSS vector")
	}
	if strings.Contains(html, `xss"><img`) {
		t.Fatal("rule_id broke out of its attribute/element context")
	}
	// It must still be VISIBLE (escaped), or we have silently dropped the evidence.
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("payload should appear escaped so the reader can still see the evidence")
	}
	if !strings.Contains(html, "&#34;&gt;&lt;img") {
		t.Error("expected the rule_id payload escaped, not stripped")
	}
}

// A tenant name carrying markup must not escape through the prose path either — narrativeSummary
// feeds inlineMarkup, which is the one function that emits markup.
func TestInlineMarkup_EscapesBeforeConverting(t *testing.T) {
	got := string(inlineMarkup("**bold** and `code` and <img src=x onerror=alert(1)>"))
	if strings.Contains(got, "<img") {
		t.Fatalf("markup passed through unescaped: %q", got)
	}
	if !strings.Contains(got, "<strong>bold</strong>") || !strings.Contains(got, "<code>code</code>") {
		t.Errorf("own constructs not converted: %q", got)
	}
	// An unpaired delimiter stays literal — we never invent a closing tag.
	if un := string(inlineMarkup("unpaired ** delimiter")); strings.Contains(un, "<strong>") {
		t.Errorf("unpaired delimiter opened a tag: %q", un)
	}
}

// The honesty rules are the report's whole value; they must hold in HTML exactly as in Markdown.
// A customer forwards the PDF, so this is the medium where a silence reading as an all-clear does
// the most damage.
func TestRenderVAPTHTML_CarriesTheHonestyMarkers(t *testing.T) {
	r := ReportFromFindings(nil, []string{"https://a.example", "https://b.example"}, "Acme", time.Now().UTC(), nil)
	r.Untested = []string{"https://a.example", "https://b.example"}
	Reassess(r)
	html := RenderVAPTHTML(r)

	if !strings.Contains(html, "Not assessed") {
		t.Error("an unassessed estate must not be rated; expected the Not assessed rating")
	}
	if !strings.Contains(html, "not assessed</b> (no scan has run against this target)") {
		t.Error("scope rows must be marked not-assessed inline")
	}
	if !strings.Contains(html, "empty result, not a clean one") {
		t.Error("the empty-findings note must distinguish nothing-found from nothing-tested")
	}
	if strings.Contains(html, "every monitored asset is currently clean") {
		t.Fatal("an unscanned estate rendered as clean — the exact false all-clear this guards")
	}
}

// Partial assessment is the third state and must survive into HTML too.
func TestRenderVAPTHTML_PartiallyAssessed(t *testing.T) {
	r := ReportFromFindings(nil, []string{"https://a.example"}, "Acme", time.Now().UTC(), nil)
	r.PartiallyAssessed = []string{"https://a.example"}
	Reassess(r)
	html := RenderVAPTHTML(r)
	if !strings.Contains(html, "partially assessed</b>") {
		t.Error("partially-assessed scope row missing")
	}
	if !strings.Contains(html, "not a clean bill of health") {
		t.Error("partial-assessment empty note missing")
	}
}

// The signals PR added these; the print deliverable must carry them, not just the Markdown one.
func TestRenderVAPTHTML_RendersSignalsAndStructure(t *testing.T) {
	due := time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC)
	f := []types.Finding{{
		ID: "f-1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical,
		Title: "Log4Shell RCE", CWE: []string{"CWE-94"}, VerificationStatus: "corroborated", Confidence: 0.9,
		ThreatIntel: &types.ThreatIntel{
			CVSS: 10.0, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", WeaponRank: "excellent",
			KEV:  &types.KEVStatus{Listed: true, Ransomware: true, DueDate: due},
			EPSS: &types.EPSSScore{Score: 0.975},
		},
	}}
	r := ReportFromFindings(f, []string{"pkg:maven/log4j-core@2.14.1"}, "Acme", time.Now().UTC(), nil)
	r.Summary.RetestConfirmed = 2
	html := RenderVAPTHTML(r)

	for _, want := range []string{
		"<!doctype html>", "@page", "Save as PDF", "no-print", // print-ready + the screen-only hint
		"ransomware-linked (CISA)", "weaponized: excellent (Metasploit)",
		"CISA remediation deadline (BOD 22-01):</b> 2021-12-24",
		"AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "97.5%", "10.0",
		"Fix verification:", "Overall risk rating: Critical",
		"Never eval or deserialize untrusted input", // CWE-94's remediation reached the page
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
	// Self-contained: no external asset may be referenced (it must render from a saved file).
	for _, bad := range []string{"<script", "src=\"http", "href=\"http", "@import"} {
		if strings.Contains(html, bad) {
			t.Errorf("report is not self-contained / carries script: found %q", bad)
		}
	}
}

func TestRenderVAPTHTML_NilIsEmpty(t *testing.T) {
	if RenderVAPTHTML(nil) != "" {
		t.Error("nil report should render empty, not a partial document")
	}
}

// Descriptions run through inlineMarkup so our own `code` spans render — which means a hostile
// description reaches a markup-emitting path. The property that makes that safe is that the path
// can emit ONLY the four hard-coded tags, none taking an attribute.
func TestRenderVAPTHTML_HostileDescriptionCannotEmitAttributes(t *testing.T) {
	f := []types.Finding{{
		ID: "f-1", RuleID: "t::r", Tool: "t", Severity: types.SeverityLow, Title: "x",
		Description: `**bold** <a href="javascript:alert(1)">click</a> <img src=x onerror=alert(1)>`,
	}}
	html := RenderVAPTHTML(ReportFromFindings(f, []string{"h"}, "Acme", time.Now().UTC(), nil))
	// No TAG may be formed and no ATTRIBUTE context entered. (The inert words "javascript:" and
	// "onerror=" do survive as escaped text — that is the evidence staying readable, not a leak.)
	for _, bad := range []string{"<a href", "<a ", "<img", `href="javascript`} {
		if strings.Contains(html, bad) {
			t.Errorf("hostile description produced live markup %q", bad)
		}
	}
	if !strings.Contains(html, "&lt;a href=") {
		t.Error("expected the anchor escaped, not stripped — the reader must see the payload")
	}
	// The ONLY tags this path may introduce are the four hard-coded ones.
	if !strings.Contains(html, "<strong>bold</strong>") {
		t.Error("our own bold span should still render")
	}
}
