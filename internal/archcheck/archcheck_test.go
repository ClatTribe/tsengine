// Package archcheck holds no runtime code. Like internal/legalcheck and internal/icpcheck, it gates
// a PUBLISHED document in CI — here the architecture reference that everyone, human and agent, reads
// instead of the source.
//
// # Why this exists
//
// arch.md said semgrep ran language-aware packs: "p/java+p/findsecbugs+p/cwe-top-25 for Java,
// p/python for Python, p/javascript+p/nodejsscan for JS". The code ran p/security-audit + p/secrets
// and had no language awareness at all. The document described the right design; it was never built;
// nothing compared the two for six weeks.
//
// That gap was not cosmetic. It is exactly why the shipped ruleset caught 3 of 12 planted
// vulnerabilities — anyone consulting arch.md would have concluded Python was covered by p/python
// and had no reason to look. A stale architecture doc is worse than no doc: it is a confident answer
// to the question you were right to ask.
//
// # What it checks, and what it deliberately does not
//
// It checks the mechanical, drift-prone half: every asset's anchor tool list in arch.md matches the
// handler's anchorNames. That is the part that changes often and silently.
//
// It does NOT try to verify prose. A test that parsed "semgrep runs p/python" out of a table cell
// would be a brittle English parser, and the fix for prose drift is the semgrep config guard below
// plus review. Mechanical claims get a machine; judgement stays with people.
package archcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// assets are the types whose anchor lists arch.md documents. mobile is excluded: §3 deprecated it,
// so its handler still exists but the doc is not expected to advertise it.
var assets = []string{"repository", "container", "web", "api", "ip", "domain", "cloud"}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// anchorNamesRe pulls the quoted tool names out of `var anchorNames = []string{ … }`.
var anchorBlockRe = regexp.MustCompile(`(?s)var anchorNames = \[\]string\{(.*?)\}`)
var quotedRe = regexp.MustCompile(`"([a-z0-9_]+)"`)

// codeAnchors reads an asset handler's declared anchor tools.
func codeAnchors(t *testing.T, root, asset string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "internal", "asset", asset, "handler.go"))
	if err != nil {
		t.Skipf("%s handler not present (%v)", asset, err)
	}
	m := anchorBlockRe.FindSubmatch(b)
	if m == nil {
		t.Skipf("%s declares no anchorNames block", asset)
	}
	var out []string
	for _, q := range quotedRe.FindAllSubmatch(m[1], -1) {
		out = append(out, string(q[1]))
	}
	sort.Strings(out)
	return out
}

// TestArchMdNamesEveryAnchorTool fails when a tool fires on every scan of an asset but the
// architecture reference does not mention it — or names one that no longer runs.
//
// Direction matters: a tool in the code and missing from the doc is the dangerous one, because a
// reader concludes we do not do something we do. Both are reported.
func TestArchMdNamesEveryAnchorTool(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "arch.md"))
	if err != nil {
		t.Skipf("arch.md not present (%v)", err)
	}
	doc := strings.ToLower(string(b))

	for _, a := range assets {
		for _, tool := range codeAnchors(t, root, a) {
			// Word-ish containment: the doc writes tools inline in prose and tables, so exact-line
			// matching would be noise. A tool named nowhere in arch.md is the real failure.
			if !strings.Contains(doc, tool) {
				t.Errorf("%s: %q fires on EVERY scan of this asset and arch.md never mentions it.\n"+
					"Anyone reading the architecture reference concludes we do not do this. Add it to "+
					"the asset's anchor table.", a, tool)
			}
		}
	}
}

// TestArchMdDescribesTheSemgrepConfigWeActuallyRun is the specific drift that cost us a vulnerability
// class, pinned so it cannot recur.
//
// arch.md claimed language-aware packs (p/python, p/javascript, p/nodejsscan, p/findsecbugs) that the
// wrapper never passed. This asserts the reference only names rulesets the code really runs.
func TestArchMdDescribesTheSemgrepConfigWeActuallyRun(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "internal", "tool", "semgrep", "semgrep.go"))
	if err != nil {
		t.Skipf("semgrep wrapper not present (%v)", err)
	}
	docB, err := os.ReadFile(filepath.Join(root, "arch.md"))
	if err != nil {
		t.Skipf("arch.md not present (%v)", err)
	}
	code, doc := string(src), string(docB)

	// Every p/<pack> arch.md attributes to semgrep must be one the wrapper passes.
	//
	// The leading boundary is load-bearing: a bare `p/[a-z-]+` also matches inside ordinary text —
	// "sqlma(p/httpx)", "fixtures/i(p/services)", "HashiCor(p/cloud-native)" — and reported three
	// phantom drifts on the first run. Require the char before `p/` to be a non-word one.
	packRe := regexp.MustCompile(`(?:^|[^\w-])(p/[a-z0-9-]+)`)

	// The CODE side must read only QUOTED packs — the actual "--config", "p/x" arguments — never
	// prose. The first version scanned the whole file, so the wrapper's own comment ("chosen over
	// p/python…") whitelisted p/python and the guard passed a mutation that re-added exactly the
	// false claim it exists to catch. A guard satisfiable by a comment is not a guard.
	codePackRe := regexp.MustCompile(`"(p/[a-z0-9-]+)"`)
	inCode := map[string]bool{}
	for _, m := range codePackRe.FindAllStringSubmatch(code, -1) {
		inCode[m[1]] = true
	}
	for _, m := range packRe.FindAllStringSubmatch(doc, -1) {
		if p := m[1]; !inCode[p] {
			t.Errorf("arch.md credits semgrep with ruleset %q, which the wrapper does not pass.\n"+
				"This is the drift that produced 3-of-12 recall: the document described language-aware "+
				"packs that were never implemented, so nobody checked. Either wire it or stop claiming it.", p)
		}
	}
}

// arch.md's L1.5 hook chain must name every hook the code actually runs.
//
// It had drifted twice by 2026-08-22: the list omitted `service_eol` and `confidence` entirely, and
// showed one flat sequence where the code runs two passes. Both omissions matter more than a missing
// line usually would, because this is the document a reader consults for the ORDER, and the order is
// load-bearing — a new hook placed by that list would land in the wrong pass. The absent `confidence`
// is the sharper one: it sets verification_status and the 0-1 scalar, which is the FP-control signal
// the incident and finding badges read, so arch.md described an engine with no confidence signal.
//
// The authority is chain.go, not either document. This test reads the constructors out of the real
// chain and asserts arch.md names each one, so the next drift fails CI instead of misleading someone.
func TestArchMdNamesEveryL15Hook(t *testing.T) {
	chain, err := os.ReadFile(filepath.Join("..", "tracer", "hooks", "chain.go"))
	if err != nil {
		t.Fatalf("read chain.go: %v", err)
	}
	arch, err := os.ReadFile(filepath.Join("..", "..", "arch.md"))
	if err != nil {
		t.Fatalf("read arch.md: %v", err)
	}
	// Constructors invoked inside the two Default* chains — the hooks that really run.
	ctor := regexp.MustCompile(`\bNew([A-Z]\w+)\(\),`)
	found := ctor.FindAllStringSubmatch(string(chain), -1)
	if len(found) < 8 {
		t.Fatalf("only %d hooks parsed from chain.go — the parser broke, not the docs", len(found))
	}
	// hookDoc maps the constructor to the name arch.md is expected to use.
	hookDoc := map[string]string{
		"FPFilter":         "fp_filter",
		"ServiceEOL":       "service_eol",
		"SurfacePriority":  "surface_priority",
		"Exploitability":   "exploitability",
		"ThreatIntel":      "threat_intel",
		"Compliance":       "compliance",
		"Corroborator":     "corroborator",
		"PostEmitVerifier": "post_emit_verifier",
		"CrossToolMerge":   "cross_tool_merge",
		"Confidence":       "confidence",
	}
	for _, m := range found {
		name := m[1]
		doc, known := hookDoc[name]
		if !known {
			t.Errorf("chain.go runs New%s() and this test does not know its arch.md name — a hook "+
				"was added without documenting it here, which is how the list drifted before", name)
			continue
		}
		if !strings.Contains(string(arch), doc) {
			t.Errorf("arch.md never mentions %q, but chain.go runs New%s() — arch.md is the document "+
				"people read instead of the source", doc, name)
		}
	}
}
