// Package reachability answers the question that turns SCA noise into a finding:
// a scanner says a dependency has a vulnerable function — does THIS codebase
// actually call it? It builds a real call graph from source (stdlib go/parser, no
// external deps) and reports whether an application entrypoint has a path to the
// vulnerable symbol. The verdict is GROUNDED — "reachable" cites the actual call
// path; "not reachable" means no static path was found (best-effort, like every
// reachability tool — the absence of a path lowers priority, it doesn't prove
// safety).
//
// Today the extractor is Go-first (the solver + triage are language-agnostic; only
// extract.go is per-language). It resolves package-qualified external calls
// (`vuln.Bad()`) and intra-repo function calls (free functions, same-package and
// cross-package via go.mod module resolution). It does NOT resolve interface /
// reflection dispatch — the standard, documented limitation.
package reachability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FuncID uniquely identifies a function in the repo, e.g. "internal/util/Process"
// or, for root package main, "main".
type FuncID string

// ExtRef is a call into a dependency package (a candidate vulnerable-symbol hit).
type ExtRef struct {
	ImportPath string `json:"import_path"`
	Symbol     string `json:"symbol"`
}

// Func is one function/method defined in the repo + the calls it makes.
type Func struct {
	ID            FuncID   `json:"id"`
	Pkg           string   `json:"pkg"` // repo-relative dir ("." for root)
	Name          string   `json:"name"`
	Exported      bool     `json:"exported"`
	IsMain        bool     `json:"is_main"`
	LocalCalls    []FuncID `json:"local_calls,omitempty"`
	ExternalCalls []ExtRef `json:"external_calls,omitempty"`
}

// Graph is the extracted call graph.
type Graph struct {
	Module   string              `json:"module"`
	Lang     string              `json:"lang,omitempty"`     // "go" | "javascript" | "python" — the extractor that built it
	Fidelity Fidelity            `json:"fidelity,omitempty"` // how precise this graph's evidence is (§10 honesty)
	Funcs    map[FuncID]*Func    `json:"funcs"`
	index    map[string][]FuncID // (pkgdir \x00 name) -> free funcs, for local-call resolution
}

type importTarget struct {
	local bool
	dir   string // repo-relative dir when local
	path  string // import path when external
}

// pending local call to resolve in pass 2.
type localRef struct {
	dir, name string
}

// Extract builds the Go call graph rooted at dir — the package-level entry point kept
// for back-compat (callers: cmd/tsengine, gate). It is GoExtractor's implementation;
// for polyglot repos use BuildGraphs / the Extractor registry.
func Extract(root string) (*Graph, error) {
	return extractGo(root)
}

// extractGo builds the call graph rooted at dir. Skips vendor/, testdata/, .git/,
// and _test.go files (production reachability).
func extractGo(root string) (*Graph, error) {
	module := readModulePath(root)
	g := &Graph{Module: module, Lang: "go", Fidelity: FidelityCallGraph, Funcs: map[FuncID]*Func{}, index: map[string][]FuncID{}}
	fset := token.NewFileSet()
	pending := map[FuncID][]localRef{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate unreadable entries
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // skip files that don't parse; don't fail the whole repo
		}
		reldir := relDir(root, path)
		imports := fileImports(file, module)

		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			isMethod := fd.Recv != nil
			id := mkFuncID(reldir, declName(fd))
			f := &Func{
				ID: id, Pkg: reldir, Name: fd.Name.Name,
				Exported: fd.Name.IsExported(),
				IsMain:   file.Name.Name == "main" && fd.Name.Name == "main" && !isMethod,
			}
			var refs []localRef
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					// bare call f() — a same-package free function
					refs = append(refs, localRef{dir: reldir, name: fun.Name})
				case *ast.SelectorExpr:
					x, ok := fun.X.(*ast.Ident)
					if !ok {
						return true
					}
					if tgt, ok := imports[x.Name]; ok {
						if tgt.local {
							refs = append(refs, localRef{dir: tgt.dir, name: fun.Sel.Name})
						} else {
							f.ExternalCalls = append(f.ExternalCalls, ExtRef{ImportPath: tgt.path, Symbol: fun.Sel.Name})
						}
					}
					// else x is a var/receiver/type → unresolved without go/types; skip
				}
				return true
			})
			g.Funcs[id] = f
			pending[id] = refs
			if !isMethod {
				key := reldir + "\x00" + fd.Name.Name
				g.index[key] = append(g.index[key], id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// pass 2: resolve local call names → existing FuncIDs
	for id, refs := range pending {
		f := g.Funcs[id]
		seen := map[FuncID]bool{}
		for _, r := range refs {
			for _, callee := range g.index[r.dir+"\x00"+r.name] {
				if callee != id && !seen[callee] {
					seen[callee] = true
					f.LocalCalls = append(f.LocalCalls, callee)
				}
			}
		}
	}
	return g, nil
}

func fileImports(file *ast.File, module string) map[string]importTarget {
	m := map[string]importTarget{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := lastSegment(p)
		if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
			name = imp.Name.Name
		}
		if module != "" && (p == module || strings.HasPrefix(p, module+"/")) {
			dir := "."
			if p != module {
				dir = strings.TrimPrefix(p, module+"/")
			}
			m[name] = importTarget{local: true, dir: dir}
		} else {
			m[name] = importTarget{local: false, path: p}
		}
	}
	return m
}

func declName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return recvType(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func recvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return recvType(t.X)
	case *ast.IndexExpr: // generic receiver T[U]
		return recvType(t.X)
	}
	return "?"
}

func mkFuncID(reldir, name string) FuncID {
	if reldir == "." {
		return FuncID(name)
	}
	return FuncID(reldir + "/" + name)
}

func relDir(root, path string) string {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return "."
	}
	return filepath.ToSlash(rel)
}

func lastSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func readModulePath(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // operator-provided repo root
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}
