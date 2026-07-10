package reachability

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// js.go is the JavaScript/TypeScript extractor at import_use fidelity: it resolves which
// npm packages are imported and whether their symbols are actually CALLED from code an
// entrypoint reaches. It is deliberately pure-Go and host-side (no node_modules, no
// runtime) — a lexer-lite pass that blanks comments/strings so matches never fire inside
// a literal, then extracts imports, function bodies, and call sites. It does NOT resolve
// cross-file dynamic dispatch (that's the call_graph-tier upgrade via an OSS engine like
// Jelly, run as a sandbox tool) — so its verdicts are stamped FidelityImportUse and a
// "not reachable" is honestly a soft negative (§10).

// JSExtractor implements Extractor for JavaScript/TypeScript.
type JSExtractor struct{}

func (JSExtractor) Lang() string { return "javascript" }

func (JSExtractor) Detect(root string) bool {
	return fileExists(filepath.Join(root, "package.json"))
}

var jsFileExt = map[string]bool{
	".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true,
}

func (JSExtractor) Extract(root string) (*Graph, error) {
	g := &Graph{Lang: "javascript", Fidelity: FidelityImportUse, Funcs: map[FuncID]*Func{}, index: map[string][]FuncID{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", "build", "out", "vendor", "coverage", ".next":
				return filepath.SkipDir
			}
			return nil
		}
		if !jsFileExt[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasSuffix(base, ".d.ts") {
			return nil // production reachability: skip tests + type-only decls
		}
		src, rerr := os.ReadFile(path) //nolint:gosec // operator-provided repo root
		if rerr != nil {
			return nil
		}
		rel := relDir(root, path)
		fileKey := relFile(root, path)
		extractJSFile(g, fileKey, rel, string(src))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// import bindings for a file: local name → npm spec, plus whether it's a namespace/default
// (symbol unknown → "") or a named import (symbol == the imported identifier).
type jsImport struct {
	spec   string // npm package path e.g. "lodash", "lodash/merge", "@scope/pkg"
	symbol string // named import symbol; "" for default/namespace
	local  bool   // a relative import (./x) — not an external package
}

var (
	reImportFrom = regexp.MustCompile(`(?m)^\s*import\s+(.+?)\s+from\s+['"]([^'"]+)['"]`)
	reRequire    = regexp.MustCompile(`(?m)(?:const|let|var)\s+(.+?)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	reFuncDecl   = regexp.MustCompile(`(?m)(export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`)
	reArrowConst = regexp.MustCompile(`(?m)(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>`)
	reCall       = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*(?:\.\s*([A-Za-z_$][\w$]*)\s*)?\(`)
	reIdent      = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
)

func extractJSFile(g *Graph, fileKey, rel, raw string) {
	src := blankLiterals(raw)
	// Imports are parsed from a comments-only-blanked view so the package spec (a string
	// literal like 'lodash') survives; the line-start anchor rejects in-string false imports.
	imports := parseJSImports(blankComments(raw))

	// The module top-level runs on import → its own entrypoint (IsMain). Every top-level
	// package call is reachable by construction.
	modID := FuncID(fileKey + "::<module>")
	mod := &Func{ID: modID, Pkg: rel, Name: "<module>", IsMain: true}
	g.Funcs[modID] = mod

	// Find function/arrow definitions + their brace-delimited body spans.
	defs := jsFuncSpans(src)
	// Register each def as a Func.
	spanOf := map[FuncID][2]int{}
	for _, d := range defs {
		id := FuncID(fileKey + "::" + d.name)
		g.Funcs[id] = &Func{ID: id, Pkg: rel, Name: d.name, Exported: d.exported}
		spanOf[id] = [2]int{d.start, d.end}
		g.index[rel+"\x00"+d.name] = append(g.index[rel+"\x00"+d.name], id)
	}

	// Assign each call site to the innermost enclosing def, else the module.
	for _, c := range findJSCalls(src) {
		owner := modID
		best := -1
		for id, sp := range spanOf {
			if c.pos >= sp[0] && c.pos < sp[1] {
				if sp[0] > best { // innermost (latest-starting) enclosing span
					best = sp[0]
					owner = id
				}
			}
		}
		f := g.Funcs[owner]
		resolveJSCall(f, g, rel, imports, c)
	}
}

// resolveJSCall attaches a call to external (imported package) or local edges.
func resolveJSCall(f *Func, g *Graph, rel string, imports map[string]jsImport, c jsCall) {
	if c.recv != "" {
		// alias.method(...) — is alias an imported package?
		if imp, ok := imports[c.recv]; ok && !imp.local {
			f.ExternalCalls = append(f.ExternalCalls, ExtRef{ImportPath: imp.spec, Symbol: c.method})
			return
		}
		return // some other object.method — unresolved without types (import_use limit)
	}
	// bare name(...) — a named/default import call, or a same-file local function.
	if imp, ok := imports[c.name]; ok && !imp.local {
		f.ExternalCalls = append(f.ExternalCalls, ExtRef{ImportPath: imp.spec, Symbol: imp.symbol})
		return
	}
	for _, callee := range g.index[rel+"\x00"+c.name] {
		if callee != f.ID {
			f.LocalCalls = appendUniqueID(f.LocalCalls, callee)
		}
	}
}

func parseJSImports(src string) map[string]jsImport {
	out := map[string]jsImport{}
	add := func(name, spec, symbol string) {
		if name == "" {
			return
		}
		out[name] = jsImport{spec: spec, symbol: symbol, local: isRelative(spec)}
	}
	for _, m := range reImportFrom.FindAllStringSubmatch(src, -1) {
		clause, spec := strings.TrimSpace(m[1]), m[2]
		parseImportClause(clause, spec, add)
	}
	for _, m := range reRequire.FindAllStringSubmatch(src, -1) {
		clause, spec := strings.TrimSpace(m[1]), m[2]
		// const _ = require('lodash')  OR  const { get } = require('lodash')
		if strings.HasPrefix(clause, "{") {
			for _, name := range destructured(clause) {
				add(name, spec, name)
			}
		} else if reIdent.MatchString(clause) {
			add(clause, spec, "")
		}
	}
	return out
}

// parseImportClause handles: `_`, `* as _`, `{ get, merge }`, `def, { named }`.
func parseImportClause(clause, spec string, add func(name, spec, symbol string)) {
	for _, part := range splitTopLevelCommas(clause) {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
		case strings.HasPrefix(part, "{"):
			for _, name := range destructured(part) {
				add(name, spec, name) // named import: symbol == local (ignoring `as` rename nuance)
			}
		case strings.HasPrefix(part, "*"):
			// * as ns
			if i := strings.LastIndex(part, " "); i >= 0 {
				add(strings.TrimSpace(part[i+1:]), spec, "")
			}
		default:
			add(part, spec, "") // default import
		}
	}
}

// destructured returns the identifiers in a `{ a, b as c }` clause (local name for `as`).
func destructured(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(strings.TrimSpace(s), "}")
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if i := strings.Index(strings.ToLower(tok), " as "); i >= 0 {
			tok = strings.TrimSpace(tok[i+4:]) // the local alias
		}
		if reIdent.MatchString(tok) {
			out = append(out, tok)
		}
	}
	return out
}

type jsFuncSpan struct {
	name     string
	exported bool
	start    int
	end      int
}

// jsFuncSpans finds function declarations + arrow consts and their body brace spans.
func jsFuncSpans(src string) []jsFuncSpan {
	var out []jsFuncSpan
	collect := func(re *regexp.Regexp) {
		for _, loc := range re.FindAllStringSubmatchIndex(src, -1) {
			exported := loc[2] >= 0
			name := src[loc[4]:loc[5]]
			// body starts at the first '{' at/after the match end.
			brace := strings.IndexByte(src[loc[1]:], '{')
			if brace < 0 {
				continue
			}
			start := loc[1] + brace
			end := matchBrace(src, start)
			if end < 0 {
				end = len(src)
			}
			out = append(out, jsFuncSpan{name: name, exported: exported, start: start, end: end})
		}
	}
	collect(reFuncDecl)
	collect(reArrowConst)
	return out
}

type jsCall struct {
	recv   string // receiver for member calls: alias in `alias.method()`
	method string // method name for member calls
	name   string // callee for bare calls
	pos    int
}

func findJSCalls(src string) []jsCall {
	var out []jsCall
	for _, loc := range reCall.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		if jsKeyword[name] {
			continue
		}
		// a `function foo(` declaration header is not a call to foo.
		if loc[4] < 0 && precededByWord(src, loc[2], "function") {
			continue
		}
		c := jsCall{pos: loc[0]}
		if loc[4] >= 0 { // member call recv.method(
			c.recv = name
			c.method = src[loc[4]:loc[5]]
		} else {
			c.name = name
		}
		out = append(out, c)
	}
	return out
}

var jsKeyword = map[string]bool{
	"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true,
	"function": true, "async": true, "await": true, "typeof": true, "new": true, "super": true,
	"else": true, "do": true, "in": true, "of": true, "yield": true, "void": true, "delete": true,
}

func isRelative(spec string) bool {
	return strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/")
}

func appendUniqueID(s []FuncID, id FuncID) []FuncID {
	for _, x := range s {
		if x == id {
			return s
		}
	}
	return append(s, id)
}

func relFile(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}
