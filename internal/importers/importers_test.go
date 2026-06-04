package importers

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

var now = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

const sarifFixture = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [
      {"id": "js/sql-injection",
       "shortDescription": {"text": "Database query built from user-controlled sources"},
       "defaultConfiguration": {"level": "error"},
       "properties": {"security-severity": "8.8", "tags": ["security", "external/cwe/cwe-089"]}},
      {"id": "js/clear-text-logging",
       "shortDescription": {"text": "Clear-text logging of sensitive information"},
       "properties": {"security-severity": "5.3", "tags": ["external/cwe/cwe-312"]}}
    ]}},
    "results": [
      {"ruleId": "js/sql-injection", "level": "error",
       "message": {"text": "This query depends on a user-provided value."},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.js"}, "region": {"startLine": 42}}}]},
      {"ruleId": "js/clear-text-logging", "level": "warning",
       "message": {"text": "Sensitive data logged."},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/log.js"}, "region": {"startLine": 7}}}]}
    ]
  }]
}`

func TestSARIF(t *testing.T) {
	if Detect([]byte(sarifFixture)) != FormatSARIF {
		t.Fatal("SARIF not auto-detected")
	}
	scan, err := Import([]byte(sarifFixture), FormatAuto, "myrepo", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.FindingsEnriched) != 2 {
		t.Fatalf("want 2 findings, got %d", len(scan.FindingsEnriched))
	}
	f := scan.FindingsEnriched[0]
	if f.Tool != "CodeQL" {
		t.Errorf("tool = %q", f.Tool)
	}
	if f.Severity != types.SeverityHigh { // 8.8 → high
		t.Errorf("severity = %q, want high (CVSS 8.8)", f.Severity)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("CWE = %v, want [CWE-89]", f.CWE)
	}
	if f.Endpoint != "src/db.js:42" {
		t.Errorf("endpoint = %q", f.Endpoint)
	}
	if scan.FindingsEnriched[1].Severity != types.SeverityMedium { // 5.3 → medium
		t.Errorf("2nd severity = %q, want medium", scan.FindingsEnriched[1].Severity)
	}
}

const snykFixture = `{
  "projectName": "myapp",
  "displayTargetFile": "package.json",
  "vulnerabilities": [
    {"id": "SNYK-JS-LODASH-567746", "title": "Prototype Pollution", "severity": "high",
     "packageName": "lodash", "version": "4.17.11",
     "identifiers": {"CVE": ["CVE-2019-10744"], "CWE": ["CWE-400"]},
     "from": ["myapp@1.0.0", "lodash@4.17.11"]}
  ]
}`

func TestSnyk(t *testing.T) {
	if Detect([]byte(snykFixture)) != FormatSnyk {
		t.Fatal("Snyk not auto-detected")
	}
	scan, err := Import([]byte(snykFixture), FormatAuto, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.FindingsEnriched) != 1 || scan.Asset.Target != "myapp" {
		t.Fatalf("snyk import wrong: %+v", scan.FindingsEnriched)
	}
	f := scan.FindingsEnriched[0]
	if f.Severity != types.SeverityHigh || f.Endpoint != "lodash@4.17.11" || f.CWE[0] != "CWE-400" {
		t.Errorf("snyk finding wrong: %+v", f)
	}

	// SCA extraction for reachability
	sca, err := ImportSCA([]byte(snykFixture), FormatSnyk)
	if err != nil {
		t.Fatal(err)
	}
	if len(sca) != 1 || sca[0].Package != "lodash" || sca[0].CVE != "CVE-2019-10744" {
		t.Errorf("SnykToSCA wrong: %+v", sca)
	}
}

const dependabotFixture = `[
  {"number": 1, "state": "open",
   "security_advisory": {"summary": "Path traversal in tar", "severity": "high", "cve_id": "CVE-2021-37701",
     "cwes": [{"cwe_id": "CWE-22"}]},
   "security_vulnerability": {"package": {"name": "tar", "ecosystem": "npm"}, "vulnerable_version_range": "< 6.1.2"}},
  {"number": 2, "state": "fixed",
   "security_advisory": {"summary": "old fixed one", "severity": "critical", "cve_id": "CVE-2020-0001", "cwes": []},
   "security_vulnerability": {"package": {"name": "olddep", "ecosystem": "npm"}, "vulnerable_version_range": "*"}}
]`

func TestDependabot(t *testing.T) {
	if Detect([]byte(dependabotFixture)) != FormatDependabot {
		t.Fatal("Dependabot not auto-detected")
	}
	scan, err := Import([]byte(dependabotFixture), FormatAuto, "org/repo", now)
	if err != nil {
		t.Fatal(err)
	}
	// only the OPEN alert is imported (the fixed one is dropped)
	if len(scan.FindingsEnriched) != 1 {
		t.Fatalf("want 1 open finding, got %d", len(scan.FindingsEnriched))
	}
	f := scan.FindingsEnriched[0]
	if f.Severity != types.SeverityHigh || f.Endpoint != "tar" || f.CWE[0] != "CWE-22" {
		t.Errorf("dependabot finding wrong: %+v", f)
	}
	sca, _ := ImportSCA([]byte(dependabotFixture), FormatDependabot)
	if len(sca) != 1 || sca[0].Package != "tar" {
		t.Errorf("DependabotToSCA wrong: %+v", sca)
	}
}

func TestUnrecognized(t *testing.T) {
	if _, err := Import([]byte(`{"hello":"world"}`), FormatAuto, "", now); err == nil {
		t.Error("unrecognized input should error")
	}
}
