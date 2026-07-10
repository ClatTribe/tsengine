package reachability

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// python.go is the Python extractor at import_use fidelity — the sibling of js.go. It
// resolves which PyPI packages are imported and whether their symbols are CALLED from
// code an entrypoint reaches. Pure-Go, host-side, no interpreter. Python scopes by
// INDENTATION (not braces), so def bodies are indentation spans; module top-level runs on
// import, so it is its own entrypoint (<module>, IsMain). Dynamic dispatch (getattr,
// decorators rebinding) is not resolved → FidelityImportUse, soft negatives (§10).

// PythonExtractor implements Extractor for Python.
type PythonExtractor struct{}

func (PythonExtractor) Lang() string { return "python" }

func (PythonExtractor) Detect(root string) bool {
	for _, m := range []string{"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "poetry.lock"} {
		if fileExists(filepath.Join(root, m)) {
			return true
		}
	}
	return false
}

func (PythonExtractor) Extract(root string) (*Graph, error) {
	g := &Graph{Lang: "python", Fidelity: FidelityImportUse, Funcs: map[FuncID]*Func{}, index: map[string][]FuncID{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".venv", "venv", "env", "__pycache__", ".git", "build", "dist", "node_modules", ".tox", ".eggs":
				return filepath.SkipDir
			}
			if strings.HasSuffix(d.Name(), ".egg-info") || strings.Contains(path, "site-packages") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".py" {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") || base == "conftest.py" {
			return nil
		}
		src, rerr := os.ReadFile(path) //nolint:gosec // operator-provided repo root
		if rerr != nil {
			return nil
		}
		extractPyFile(g, relFile(root, path), relDir(root, path), string(src))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

var (
	rePyImport     = regexp.MustCompile(`(?m)^\s*import\s+(.+)$`)
	rePyFromImport = regexp.MustCompile(`(?m)^\s*from\s+([.\w]+)\s+import\s+(.+)$`)
	rePyDef        = regexp.MustCompile(`^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
	rePyCall       = regexp.MustCompile(`([A-Za-z_][\w.]*)\s*\(`)
)

func extractPyFile(g *Graph, fileKey, rel, raw string) {
	src := blankPy(raw)
	imports := parsePyImports(src) // local name → jsImport (reused shape: spec/symbol/local)

	modID := FuncID(fileKey + "::<module>")
	g.Funcs[modID] = &Func{ID: modID, Pkg: rel, Name: "<module>", IsMain: true}

	spans := pyFuncSpans(src)
	spanOf := map[FuncID][2]int{}
	for _, s := range spans {
		id := FuncID(fileKey + "::" + s.name)
		// public-by-convention (no leading underscore) == library entry surface.
		g.Funcs[id] = &Func{ID: id, Pkg: rel, Name: s.name, Exported: !strings.HasPrefix(s.name, "_")}
		spanOf[id] = [2]int{s.start, s.end}
		g.index[rel+"\x00"+s.name] = append(g.index[rel+"\x00"+s.name], id)
	}

	for _, c := range findPyCalls(src) {
		owner := modID
		best := -1
		for id, sp := range spanOf {
			if c.pos >= sp[0] && c.pos < sp[1] && sp[0] > best {
				best = sp[0]
				owner = id
			}
		}
		resolvePyCall(g.Funcs[owner], g, rel, imports, c)
	}
}

func resolvePyCall(f *Func, g *Graph, rel string, imports map[string]jsImport, c jsCall) {
	if c.recv != "" {
		if imp, ok := imports[c.recv]; ok && !imp.local {
			f.ExternalCalls = append(f.ExternalCalls, ExtRef{ImportPath: imp.spec, Symbol: c.method})
		}
		return
	}
	if imp, ok := imports[c.name]; ok && !imp.local {
		sym := imp.symbol
		f.ExternalCalls = append(f.ExternalCalls, ExtRef{ImportPath: imp.spec, Symbol: sym})
		return
	}
	for _, callee := range g.index[rel+"\x00"+c.name] {
		if callee != f.ID {
			f.LocalCalls = appendUniqueID(f.LocalCalls, callee)
		}
	}
}

func parsePyImports(src string) map[string]jsImport {
	out := map[string]jsImport{}
	// import a, b.c as d, e
	for _, m := range rePyImport.FindAllStringSubmatch(src, -1) {
		for _, part := range strings.Split(m[1], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			spec := part
			local := ""
			if i := strings.Index(strings.ToLower(part), " as "); i >= 0 {
				spec = strings.TrimSpace(part[:i])
				local = strings.TrimSpace(part[i+4:])
			} else {
				local = strings.SplitN(spec, ".", 2)[0] // `import a.b` binds `a`
			}
			if local != "" {
				out[local] = jsImport{spec: spec, symbol: "", local: strings.HasPrefix(spec, ".")}
			}
		}
	}
	// from pkg import a, b as c   (pkg may be "." relative)
	for _, m := range rePyFromImport.FindAllStringSubmatch(src, -1) {
		spec := strings.TrimSpace(m[1])
		names := strings.TrimSpace(m[2])
		names = strings.Trim(names, "()")
		rel := strings.HasPrefix(spec, ".")
		for _, part := range strings.Split(names, ",") {
			part = strings.TrimSpace(part)
			if part == "" || part == "*" {
				continue
			}
			sym, local := part, part
			if i := strings.Index(strings.ToLower(part), " as "); i >= 0 {
				sym = strings.TrimSpace(part[:i])
				local = strings.TrimSpace(part[i+4:])
			}
			out[local] = jsImport{spec: spec, symbol: sym, local: rel}
		}
	}
	return out
}

type pySpan struct {
	name  string
	start int
	end   int
}

// pyFuncSpans finds def/async-def and their indentation-delimited body char spans.
func pyFuncSpans(src string) []pySpan {
	lines := strings.SplitAfter(src, "\n")
	offsets := make([]int, len(lines))
	pos := 0
	for i, ln := range lines {
		offsets[i] = pos
		pos += len(ln)
	}
	var out []pySpan
	for i, ln := range lines {
		m := rePyDef.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		indent := len(m[1])
		start := offsets[i]
		end := len(src)
		for j := i + 1; j < len(lines); j++ {
			body := lines[j]
			if strings.TrimSpace(body) == "" {
				continue // blank lines belong to the body
			}
			if leadingWS(body) <= indent {
				end = offsets[j]
				break
			}
		}
		out = append(out, pySpan{name: m[2], start: start, end: end})
	}
	return out
}

func findPyCalls(src string) []jsCall {
	var out []jsCall
	for _, loc := range rePyCall.FindAllStringSubmatchIndex(src, -1) {
		dotted := src[loc[2]:loc[3]]
		if pyKeyword[dotted] {
			continue
		}
		// a `def foo(` / `class Foo(` declaration header is not a call.
		if !strings.Contains(dotted, ".") && (precededByWord(src, loc[2], "def") || precededByWord(src, loc[2], "class")) {
			continue
		}
		c := jsCall{pos: loc[0]}
		if i := strings.LastIndex(dotted, "."); i >= 0 {
			c.recv = strings.SplitN(dotted, ".", 2)[0]
			c.method = dotted[i+1:]
		} else {
			c.name = dotted
		}
		out = append(out, c)
	}
	return out
}

var pyKeyword = map[string]bool{
	"if": true, "elif": true, "for": true, "while": true, "with": true, "return": true,
	"def": true, "class": true, "print": true, "and": true, "or": true, "not": true,
	"in": true, "is": true, "lambda": true, "yield": true, "assert": true, "del": true,
	"raise": true, "except": true, "import": true, "from": true, "as": true, "await": true,
}

func leadingWS(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
		} else if r == '\t' {
			n += 4
		} else {
			break
		}
	}
	return n
}

// blankPy blanks Python # comments and ' " ”' """ string literals (length-preserving).
func blankPy(src string) string {
	b := []byte(src)
	n := len(b)
	out := make([]byte, n)
	copy(out, b)
	blank := func(i int) {
		if b[i] != '\n' {
			out[i] = ' '
		}
	}
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '#':
			for i < n && b[i] != '\n' {
				blank(i)
				i++
			}
		case (c == '"' || c == '\'') && i+2 < n && b[i+1] == c && b[i+2] == c:
			q := c
			blank(i)
			blank(i + 1)
			blank(i + 2)
			i += 3
			for i < n {
				if b[i] == q && i+2 < n && b[i+1] == q && b[i+2] == q {
					blank(i)
					blank(i + 1)
					blank(i + 2)
					i += 3
					break
				}
				blank(i)
				i++
			}
		case c == '"' || c == '\'':
			q := c
			blank(i)
			i++
			for i < n && b[i] != '\n' {
				if b[i] == '\\' {
					blank(i)
					if i+1 < n {
						blank(i + 1)
					}
					i += 2
					continue
				}
				if b[i] == q {
					blank(i)
					i++
					break
				}
				blank(i)
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}
