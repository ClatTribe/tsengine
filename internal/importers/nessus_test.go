package importers

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/fixunit"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A .nessus v2 export as Nessus / Tenable.io writes it: one host, one critical plugin naming two CVEs
// (plus one malformed entry), one medium plugin with no CVE, and one informational plugin.
const nessusFixture = `<?xml version="1.0" ?>
<NessusClientData_v2>
 <Report name="quarterly-external">
  <ReportHost name="10.0.0.5">
   <HostProperties>
    <tag name="host-ip">10.0.0.5</tag>
    <tag name="host-fqdn">web01.acme.example</tag>
   </HostProperties>
   <ReportItem port="443" svc_name="www" protocol="tcp" severity="4" pluginID="156860" pluginName="Apache Log4j RCE" pluginFamily="Web Servers">
    <synopsis>The remote host runs a vulnerable Log4j.</synopsis>
    <description>JNDI lookups allow remote code execution.</description>
    <solution>Upgrade to Log4j 2.17.1 or later.</solution>
    <plugin_output>Path : /opt/app/lib/log4j-core-2.14.1.jar</plugin_output>
    <cve>CVE-2021-45046</cve>
    <cve>CVE-2021-44228</cve>
    <cve>not-a-cve</cve>
    <cwe>502</cwe>
    <cvss3_base_score>10.0</cvss3_base_score>
    <exploit_available>true</exploit_available>
   </ReportItem>
   <ReportItem port="0" svc_name="general" protocol="tcp" severity="2" pluginID="57582" pluginName="SSL Self-Signed Certificate" pluginFamily="General">
    <synopsis>The certificate is self-signed.</synopsis>
   </ReportItem>
   <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH Server Type and Version Information" pluginFamily="Service detection">
    <plugin_output>SSH version : OpenSSH_8.9</plugin_output>
   </ReportItem>
  </ReportHost>
 </Report>
</NessusClientData_v2>`

// One finding per CVE, so EVERY CVE a plugin names reaches KEV/EPSS enrichment — not just the first.
// The enrichment hook reads the CVE from the rule id, so the rule id is what is asserted.
func TestNessus_OneFindingPerCVE_EachCVEInTheRuleID(t *testing.T) {
	scan, stats, err := FromNessus([]byte(nessusFixture), "", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range scan.FindingsRaw {
		got[f.RuleID] = true
	}
	for _, want := range []string{
		"nessus::156860::CVE-2021-44228",
		"nessus::156860::CVE-2021-45046",
		"nessus::57582",
	} {
		if !got[want] {
			t.Errorf("missing finding %q; got %v", want, got)
		}
	}
	if len(scan.FindingsRaw) != 3 {
		t.Errorf("imported %d findings, want 3 (two CVEs split out, one CVE-less plugin); the malformed "+
			"<cve> must not become a finding: %v", len(scan.FindingsRaw), got)
	}
	// The same pattern the threat-intel hook uses — if this does not match, KEV/EPSS never land.
	cve := regexp.MustCompile(`CVE-\d{4}-\d{3,7}`)
	for _, f := range scan.FindingsRaw {
		if strings.Contains(f.RuleID, "::CVE") && !cve.MatchString(f.RuleID) {
			t.Errorf("rule id %q would not be read by threat-intel enrichment", f.RuleID)
		}
	}
	if stats.SkippedInformational != 1 {
		t.Errorf("skipped_informational = %d, want 1 — the severity-0 plugin must be COUNTED, not silently dropped",
			stats.SkippedInformational)
	}
}

// Splitting per CVE must not split the FIX: one Nessus plugin is one patch, so the fix plan shows one
// step. The CVE-less plugin is a different patch and must not join it.
func TestNessus_CVEsOfOnePluginShareOneFixUnit(t *testing.T) {
	scan, _, _ := FromNessus([]byte(nessusFixture), "", time.Unix(0, 0))
	keys := map[string]string{}
	for _, f := range scan.FindingsRaw {
		keys[f.RuleID] = fixunit.Key(f)
	}
	a, b := keys["nessus::156860::CVE-2021-44228"], keys["nessus::156860::CVE-2021-45046"]
	if a == "" || a != b {
		t.Errorf("the two CVEs of one plugin got different fix units %q / %q — the fix plan would show one patch as two steps", a, b)
	}
	if keys["nessus::57582"] == a {
		t.Errorf("a different plugin shares the fix unit %q — two patches would be presented as one", a)
	}
	if len(fixunit.GroupBy(scan.FindingsRaw)) != 2 {
		t.Errorf("want 2 fix groups (one per plugin), got %d", len(fixunit.GroupBy(scan.FindingsRaw)))
	}
}

// The plugin output is what the scanner actually SAW on the host; without it the finding is a claim.
// The endpoint names the host a person recognises and the port when there is one.
func TestNessus_KeepsEvidenceHostAndPort(t *testing.T) {
	scan, _, _ := FromNessus([]byte(nessusFixture), "", time.Unix(0, 0))
	for _, f := range scan.FindingsRaw {
		switch f.RuleID {
		case "nessus::156860::CVE-2021-44228":
			if f.Endpoint != "web01.acme.example:443" {
				t.Errorf("endpoint = %q, want the FQDN with the port", f.Endpoint)
			}
			if !strings.Contains(f.Description, "log4j-core-2.14.1.jar") {
				t.Errorf("plugin output (the evidence) was dropped: %q", f.Description)
			}
			if !strings.Contains(f.Description, "2.17.1") {
				t.Errorf("Nessus's own solution was dropped: %q", f.Description)
			}
			if f.Severity != types.SeverityCritical {
				t.Errorf("severity 4 mapped to %q, want critical", f.Severity)
			}
			if len(f.CWE) != 1 || f.CWE[0] != "CWE-502" {
				t.Errorf("cwe = %v, want [CWE-502]", f.CWE)
			}
			if f.VerificationStatus != "" {
				t.Errorf("an imported scanner finding must not arrive marked %q — nothing here proved it", f.VerificationStatus)
			}
		case "nessus::57582":
			if f.Endpoint != "web01.acme.example" {
				t.Errorf("port 0 is host-level; endpoint = %q, want the bare host", f.Endpoint)
			}
		}
	}
}

func TestNessus_SeverityMapping(t *testing.T) {
	for in, want := range map[string]types.Severity{
		"4": types.SeverityCritical, "3": types.SeverityHigh, "2": types.SeverityMedium,
		"1": types.SeverityLow, "0": types.SeverityInfo, "": types.SeverityInfo, "x": types.SeverityInfo,
	} {
		if got := nessusSeverity(in); got != want {
			t.Errorf("nessusSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNessus_RejectsANonNessusDocument(t *testing.T) {
	if _, _, err := FromNessus([]byte(`<NessusClientData_v2></NessusClientData_v2>`), "", time.Unix(0, 0)); err == nil {
		t.Error("a .nessus file with no <Report> must be refused, not read as a clean scan")
	}
}

// Auto-detection reads the ROOT element, so the right parser runs and a JSON report that merely
// QUOTES a Nessus root name is not misread as XML.
func TestDetect_XMLExports(t *testing.T) {
	if got := Detect([]byte(nessusFixture)); got != FormatNessus {
		t.Errorf("Detect(.nessus) = %q, want nessus", got)
	}
	if got := Detect([]byte(burpFixture)); got != FormatBurp {
		t.Errorf("Detect(burp xml) = %q, want burp", got)
	}
	if got := Detect([]byte(`<?xml version="1.0"?><html><body/></html>`)); got != FormatAuto {
		t.Errorf("unknown XML detected as %q, want auto (unrecognised)", got)
	}
	if got := Detect([]byte(`{"runs":[{"note":"<NessusClientData_v2>"}]}`)); got != FormatSARIF {
		t.Errorf("a JSON report quoting a Nessus tag was detected as %q", got)
	}
	_, stats, err := ImportWithStats([]byte(nessusFixture), FormatAuto, "", time.Unix(0, 0))
	if err != nil || stats.SkippedInformational != 1 {
		t.Errorf("auto import of .nessus: err=%v skipped=%d", err, stats.SkippedInformational)
	}
}
