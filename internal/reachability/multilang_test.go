package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree materializes a fixture repo (path→content) under a temp dir and returns root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// priorityOf finds the triage priority for a given finding id.
func priorityOf(results []TriageResult, id string) (string, Verdict) {
	for _, r := range results {
		if r.Finding.ID == id {
			return r.Priority, r.Verdict
		}
	}
	return "", Verdict{}
}

// TestJS_EndToEnd exercises the JS extractor through the same solver Go uses: a package
// called from an exported handler is REACHABLE; a package called only from a private,
// never-invoked function is DEPRIORITIZED; an imported-but-never-called package is UNUSED;
// and a package named only inside a comment/string is UNUSED (the literal-safety guard).
func TestJS_EndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0"}`,
		"src/handler.js": `
import _ from 'lodash';
import chalk from 'chalk';
export function handleOrder(req) {
  return _.merge({}, req.body);
}
export function greet() { return 'hi'; }   // chalk imported but never called
`,
		"src/dead.js": `
import minimatch from 'minimatch';
function neverCalled(a, b) {
  return minimatch(a, b);
}
`,
		"src/top.js": `
import axios from 'axios';
axios.get('/health');   // top-level → runs on import → reachable
`,
		"src/tricky.js": `
// const evil = require('sneaky'); evil.pwn();
const s = "import naughty from 'sneaky2'";
export function ok() { return 1; }
`,
	})

	graphs := BuildGraphs(root)
	g := graphs["javascript"]
	if g == nil {
		t.Fatal("javascript graph must be built when package.json is present")
	}
	if g.Fidelity != FidelityImportUse {
		t.Errorf("JS graph fidelity = %q, want import_use", g.Fidelity)
	}

	findings := []SCAFinding{
		{ID: "lodash", Package: "lodash", Ecosystem: "npm"},
		{ID: "chalk", Package: "chalk", Ecosystem: "npm"},
		{ID: "minimatch", Package: "minimatch", Ecosystem: "npm"},
		{ID: "axios", Package: "axios", Ecosystem: "npm"},
		{ID: "sneaky", Package: "sneaky", Ecosystem: "npm"},
		{ID: "sneaky2", Package: "sneaky2", Ecosystem: "npm"},
	}
	res := TriageMulti(graphs, findings)

	want := map[string]string{
		"lodash":    "reachable",     // exported handler calls _.merge
		"axios":     "reachable",     // top-level call
		"minimatch": "deprioritized", // called only from a private, uncalled function
		"chalk":     "unused",        // imported, never invoked
		"sneaky":    "unused",        // only in a comment
		"sneaky2":   "unused",        // only in a string literal
	}
	for id, wantPr := range want {
		gotPr, v := priorityOf(res, id)
		if gotPr != wantPr {
			t.Errorf("%s: priority = %q, want %q (verdict=%+v)", id, gotPr, wantPr, v)
		}
		if gotPr == "reachable" && len(v.Path) == 0 {
			t.Errorf("%s: reachable verdict must cite a path", id)
		}
		if v.Lang != "javascript" {
			t.Errorf("%s: verdict lang = %q, want javascript", id, v.Lang)
		}
	}
}

// TestPython_EndToEnd is the Python sibling of the JS test.
func TestPython_EndToEnd(t *testing.T) {
	root := writeTree(t, map[string]string{
		"requirements.txt": "requests==2.0\njinja2==3.0\nlxml==4.0\n",
		"app.py": `
import requests
import jinja2   # imported but never called
from lxml import etree

def handler(url):
    return requests.get(url)

def _dead():
    return etree.parse('x')   # lxml (etree) called only from a private, uncalled func
`,
		"tricky.py": `
# import evilmod
s = "import evilmod2"
def ok():
    return 1
`,
	})

	graphs := BuildGraphs(root)
	g := graphs["python"]
	if g == nil {
		t.Fatal("python graph must be built when requirements.txt is present")
	}

	findings := []SCAFinding{
		{ID: "requests", Package: "requests", Ecosystem: "pip"},
		{ID: "jinja2", Package: "jinja2", Ecosystem: "pip"},
		{ID: "lxml", Package: "lxml", Ecosystem: "pip"},
		{ID: "evilmod", Package: "evilmod", Ecosystem: "pip"},
		{ID: "evilmod2", Package: "evilmod2", Ecosystem: "pip"},
	}
	res := TriageMulti(graphs, findings)

	want := map[string]string{
		"requests": "reachable",     // public handler() calls requests.get
		"lxml":     "deprioritized", // etree.parse only in private _dead()
		"jinja2":   "unused",        // imported, never called
		"evilmod":  "unused",        // comment only
		"evilmod2": "unused",        // string only
	}
	for id, wantPr := range want {
		gotPr, v := priorityOf(res, id)
		if gotPr != wantPr {
			t.Errorf("%s: priority = %q, want %q (verdict=%+v)", id, gotPr, wantPr, v)
		}
	}
}

// TestPolyglot_BuildsBothGraphsAndRoutesByEcosystem: one repo with JS + Python gets both
// graphs, and each finding is triaged against the graph for ITS ecosystem.
func TestPolyglot_BuildsBothGraphsAndRoutesByEcosystem(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json":     `{"name":"app"}`,
		"requirements.txt": "requests==2.0\n",
		"web/index.js":     "import _ from 'lodash';\nexport function h(r){ return _.get(r,'a'); }\n",
		"api/app.py":       "import requests\ndef handler():\n    return requests.get('x')\n",
	})
	graphs := BuildGraphs(root)
	if graphs["javascript"] == nil || graphs["python"] == nil {
		t.Fatalf("polyglot repo must build both graphs, got %v", keys(graphs))
	}
	res := TriageMulti(graphs, []SCAFinding{
		{ID: "lodash", Package: "lodash", Ecosystem: "npm"},
		{ID: "requests", Package: "requests", Ecosystem: "pip"},
	})
	if pr, _ := priorityOf(res, "lodash"); pr != "reachable" {
		t.Errorf("lodash (npm) should route to the JS graph and be reachable, got %q", pr)
	}
	if pr, _ := priorityOf(res, "requests"); pr != "reachable" {
		t.Errorf("requests (pip) should route to the Python graph and be reachable, got %q", pr)
	}
}

// TestTriageMulti_UnknownEcosystemIsHonest: a finding whose ecosystem has no built graph is
// reported unknown_ecosystem — never silently "safe" (§10).
func TestTriageMulti_UnknownEcosystemIsHonest(t *testing.T) {
	root := writeTree(t, map[string]string{"package.json": `{"name":"a"}`, "i.js": "export function f(){return 1}"})
	graphs := BuildGraphs(root)
	res := TriageMulti(graphs, []SCAFinding{{ID: "x", Package: "some-gem", Ecosystem: "rubygems"}})
	if pr, _ := priorityOf(res, "x"); pr != "unknown_ecosystem" {
		t.Errorf("a ruby finding against a JS-only repo must be unknown_ecosystem, got %q", pr)
	}
}

// TestGoExtractor_StillCallGraphFidelity: the refactor preserved the Go path + stamps it.
func TestGoExtractor_StillCallGraphFidelity(t *testing.T) {
	if (GoExtractor{}).Lang() != "go" {
		t.Fatal("GoExtractor.Lang must be go")
	}
	root := writeTree(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n",
		"main.go": "package main\nimport \"example.com/app/dep\"\nfunc main(){ dep.Bad() }\n",
	})
	g, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	if g.Lang != "go" || g.Fidelity != FidelityCallGraph {
		t.Errorf("Go graph must stamp lang=go fidelity=call_graph, got lang=%q fidelity=%q", g.Lang, g.Fidelity)
	}
}

func keys(m map[string]*Graph) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
