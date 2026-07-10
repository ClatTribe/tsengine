package reachability

import (
	"os"
	"path/filepath"
)

// extractor.go makes call-graph extraction pluggable per language. The reachability
// SOLVER (Analyze/TriageSCA) and the Graph/Func/ExtRef model are language-agnostic —
// only the extraction of a Graph from source is per-language. So adding a language is
// adding an Extractor, never touching the solver (the whole leverage of this design).

// Fidelity records how precise a graph's reachability evidence is, so a verdict is
// trusted proportionally. A coarser tier's "not reachable" is weaker evidence — it must
// never be reported as a precise negative (§10: absence of a path lowers priority, it
// does not prove safety, and a heuristic extractor is honest that its negative is softer).
type Fidelity string

const (
	// FidelityCallGraph is a resolved intra-repo call graph (function → function). A
	// "reachable" verdict cites the real call path; "not reachable" means no static path
	// from an application entrypoint was found. Go today (stdlib go/parser).
	FidelityCallGraph Fidelity = "call_graph"

	// FidelityImportUse is import + call-site extraction WITHOUT full type/name resolution.
	// A "reachable" verdict still cites a real import of the vulnerable package + a call to
	// its symbol from an entrypoint-reachable function; but because method/dynamic dispatch
	// isn't resolved, its "not reachable" is a SOFTER negative than call_graph. JS/TS/Python.
	FidelityImportUse Fidelity = "import_use"
)

// Extractor builds the language-agnostic Graph from a source tree rooted at `root`.
// Detect reports whether this language's manifest/lockfile is present (so a polyglot
// repo runs the right extractors). Lang is the ecosystem key SCA findings route on.
type Extractor interface {
	Lang() string
	Detect(root string) bool
	Extract(root string) (*Graph, error)
}

// Extractors is the ordered registry of built-in extractors — one per supported language.
// The dispatcher (BuildGraphs) runs every extractor whose Detect fires on the repo.
func Extractors() []Extractor {
	return []Extractor{
		GoExtractor{},
		JSExtractor{},
		PythonExtractor{},
	}
}

// GoExtractor wraps the stdlib go/parser call-graph extractor. Host-side, pure Go, no
// deps — the reference call_graph-fidelity extractor.
type GoExtractor struct{}

func (GoExtractor) Lang() string            { return "go" }
func (GoExtractor) Detect(root string) bool { return fileExists(filepath.Join(root, "go.mod")) }
func (GoExtractor) Extract(root string) (*Graph, error) {
	return extractGo(root)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
