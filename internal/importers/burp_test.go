package importers

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

const burpFixture = `<?xml version="1.0"?>
<issues burpVersion="2024.1.1" exportTime="Mon Jan 01 00:00:00 UTC 2024">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="203.0.113.10">https://shop.acme.example</host>
    <path><![CDATA[/search]]></path>
    <location><![CDATA[/search [q parameter]]]></location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[<p>SQL injection lets an attacker <b>read the database</b>.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>Use parameterised queries.</p>]]></remediationBackground>
    <issueDetail><![CDATA[The <b>q</b> parameter appears vulnerable &amp; returned a database error.]]></issueDetail>
    <vulnerabilityClassifications><![CDATA[<ul><li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: SQL Injection</a></li><li>CWE-89 again</li></ul>]]></vulnerabilityClassifications>
  </issue>
  <issue>
    <type>5245344</type>
    <name>Cross-site scripting (DOM-based)</name>
    <host ip="203.0.113.10">https://shop.acme.example</host>
    <path><![CDATA[/profile]]></path>
    <severity>Medium</severity>
    <confidence>Tentative</confidence>
    <issueDetail><![CDATA[Data flows from location.hash into innerHTML.]]></issueDetail>
  </issue>
  <issue>
    <type>5245952</type>
    <name>Email addresses disclosed</name>
    <host ip="203.0.113.10">https://shop.acme.example</host>
    <path><![CDATA[/contact]]></path>
    <severity>Information</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>`

func TestBurp_ImportsIssuesAndCountsInformational(t *testing.T) {
	scan, stats, err := FromBurp([]byte(burpFixture), "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.FindingsRaw) != 2 {
		t.Fatalf("imported %d, want 2 (Information is counted, not imported)", len(scan.FindingsRaw))
	}
	if stats.SkippedInformational != 1 {
		t.Errorf("skipped_informational = %d, want 1", stats.SkippedInformational)
	}
	f := scan.FindingsRaw[0]
	if f.RuleID != "burp::1049088" || f.Severity != types.SeverityHigh {
		t.Errorf("rule/severity = %q/%q, want burp::1049088/high", f.RuleID, f.Severity)
	}
	if f.Endpoint != "https://shop.acme.example/search" {
		t.Errorf("endpoint = %q, want host+path", f.Endpoint)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("cwe = %v, want [CWE-89] (deduplicated)", f.CWE)
	}
	if strings.Contains(f.Description, "<b>") || strings.Contains(f.Description, "&amp;") {
		t.Errorf("Burp's HTML reached the description unrendered: %q", f.Description)
	}
	if !strings.Contains(f.Description, "parameterised queries") {
		t.Errorf("Burp's remediation was dropped: %q", f.Description)
	}
	if scan.Asset.Type != types.AssetType("web_application") || scan.Asset.Target != "https://shop.acme.example" {
		t.Errorf("asset = %+v, want web_application on the scanned host", scan.Asset)
	}
}

// A Tentative issue is Burp saying "this might be real". That doubt must survive the import in Burp's
// own word, where the reader will see it — and a Firm one must not be dressed in the same caveat.
func TestBurp_TentativeConfidenceIsStatedNotFlattened(t *testing.T) {
	scan, _, _ := FromBurp([]byte(burpFixture), "", time.Unix(0, 0))
	firm, tentative := scan.FindingsRaw[0], scan.FindingsRaw[1]
	if tentative.ToolArgs["confidence"] != "Tentative" {
		t.Errorf("confidence not carried: %q", tentative.ToolArgs["confidence"])
	}
	if !strings.Contains(tentative.Description, "Tentative") {
		t.Errorf("a Tentative issue does not say so to the reader: %q", tentative.Description)
	}
	if strings.Contains(firm.Description, "Tentative") {
		t.Errorf("a Firm issue carries the Tentative caveat: %q", firm.Description)
	}
	for _, f := range scan.FindingsRaw {
		if f.VerificationStatus != "" {
			t.Errorf("an imported Burp issue arrived marked %q — Burp observed a symptom; nothing here proved it", f.VerificationStatus)
		}
	}
}

func TestBurp_RejectsMalformedXML(t *testing.T) {
	if _, _, err := FromBurp([]byte(`<issues><issue>`), "", time.Unix(0, 0)); err == nil {
		t.Error("a truncated Burp export must be refused, not read as empty")
	}
}
