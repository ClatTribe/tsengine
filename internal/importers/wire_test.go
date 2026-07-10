package importers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/internal/reachability"
)

// TestSCAImporters_PopulateEcosystem: the importers carry the scanner's ecosystem onto the
// SCAFinding so reachability can route to the right language graph (the multi-language wiring).
func TestSCAImporters_PopulateEcosystem(t *testing.T) {
	dep, err := DependabotToSCA([]byte(dependabotFixture))
	if err != nil || len(dep) != 1 {
		t.Fatalf("dependabot sca: %v %+v", err, dep)
	}
	if dep[0].Ecosystem != "npm" {
		t.Errorf("Dependabot SCA must carry ecosystem npm, got %q", dep[0].Ecosystem)
	}
	snyk, err := SnykToSCA([]byte(snykFixture))
	if err != nil || len(snyk) != 1 {
		t.Fatalf("snyk sca: %v %+v", err, snyk)
	}
	if snyk[0].Ecosystem != "npm" {
		t.Errorf("Snyk SCA must carry ecosystem from packageManager, got %q", snyk[0].Ecosystem)
	}
}

// dependabotMultiLang is a GHAS alert set spanning three ecosystems — npm (reachable in the
// JS graph), pip (reachable in the Python graph), and maven (no graph → unknown, honest).
const dependabotMultiLang = `[
  {"number": 1, "state": "open",
   "security_advisory": {"summary": "Prototype pollution in lodash", "severity": "high", "cve_id": "CVE-2019-10744", "cwes": [{"cwe_id": "CWE-1321"}]},
   "security_vulnerability": {"package": {"name": "lodash", "ecosystem": "npm"}, "vulnerable_version_range": "< 4.17.12"}},
  {"number": 2, "state": "open",
   "security_advisory": {"summary": "ReDoS in requests", "severity": "high", "cve_id": "CVE-2023-32681", "cwes": [{"cwe_id": "CWE-400"}]},
   "security_vulnerability": {"package": {"name": "requests", "ecosystem": "pip"}, "vulnerable_version_range": "< 2.31.0"}},
  {"number": 3, "state": "open",
   "security_advisory": {"summary": "Deserialization in a java lib", "severity": "critical", "cve_id": "CVE-2022-1471", "cwes": [{"cwe_id": "CWE-502"}]},
   "security_vulnerability": {"package": {"name": "org.yaml:snakeyaml", "ecosystem": "maven"}, "vulnerable_version_range": "< 2.0"}}
]`

// TestEndToEnd_DependabotToMultiLangReachability is the FULL pipeline: a real GHAS alert
// stream → DependabotToSCA (carrying ecosystems) → BuildGraphs over a real polyglot repo →
// TriageMulti routes each CVE to ITS language graph. The npm + pip CVEs are reachable in
// their respective sources; the maven CVE has no graph and is reported unknown_ecosystem —
// never silently safe (§10). This proves multi-language reachability end to end through the
// product's own importer path, not just the library.
func TestEndToEnd_DependabotToMultiLangReachability(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"package.json":     `{"name":"web"}`,
		"requirements.txt": "requests==2.30\n",
		"web/handler.js":   "import _ from 'lodash';\nexport function handle(req){ return _.merge({}, req.body); }\n",
		"api/app.py":       "import requests\ndef view(url):\n    return requests.get(url)\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sca, err := DependabotToSCA([]byte(dependabotMultiLang))
	if err != nil {
		t.Fatal(err)
	}
	if len(sca) != 3 {
		t.Fatalf("want 3 SCA findings, got %d", len(sca))
	}

	graphs := reachability.BuildGraphsOrGo(root)
	results := reachability.TriageMulti(graphs, sca)

	byPkg := map[string]reachability.TriageResult{}
	for _, r := range results {
		byPkg[r.Finding.Package] = r
	}
	if got := byPkg["lodash"].Priority; got != "reachable" {
		t.Errorf("lodash (npm) must be reachable in the JS graph, got %q", got)
	}
	if got := byPkg["requests"].Priority; got != "reachable" {
		t.Errorf("requests (pip) must be reachable in the Python graph, got %q", got)
	}
	if got := byPkg["org.yaml:snakeyaml"].Priority; got != "unknown_ecosystem" {
		t.Errorf("a maven CVE with no built graph must be unknown_ecosystem (never silently safe), got %q", got)
	}
	// provenance: the reachable verdicts must be stamped with the language that proved them.
	if byPkg["lodash"].Verdict.Lang != "javascript" || byPkg["requests"].Verdict.Lang != "python" {
		t.Errorf("verdicts must carry language provenance: lodash=%q requests=%q",
			byPkg["lodash"].Verdict.Lang, byPkg["requests"].Verdict.Lang)
	}
}
