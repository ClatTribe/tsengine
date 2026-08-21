package threatintel

import "strings"

// nuclei_yaml_parse.go is the minimal indentation-driven YAML-subset reader behind
// DecodeNucleiTemplate. It builds a small scalar/seq/map node tree; extraction (nuclei_yaml.go)
// pulls the narrow field set out of it. Scope is exactly what a nuclei HTTP template needs:
//
//   - block mappings (`key: value`, `key:` opening a child) and block sequences (`- item`)
//   - the compact sequence-of-mappings YAML uses for matcher/request blocks (`- type: word` then
//     aligned sibling keys)
//   - block scalars (`|`, `>` with chomping indicators) — consumed even for keys we ignore, so a
//     multi-line `description:` cannot desync the following structural lines
//   - flow sequences (`["a","b"]`, `[200]`) and quoted scalars
//
// Anything outside this subset (flow maps, anchors/aliases, tags) is ignored rather than guessed at
// (the frontmatter-parser convention). Bounds guard an untrusted community feed.

const (
	maxYAMLLines  = 20000 // a template far larger than any real one — refuse rather than chew forever
	maxYAMLNodes  = 50000
	maxYAMLIndent = 200
)

type ynode struct {
	isScalar bool
	scalar   string
	seq      []*ynode
	m        map[string]*ynode
	keys     []string // insertion order of map keys
}

func scalarNode(s string) *ynode { return &ynode{isScalar: true, scalar: s} }

func (n *ynode) set(key string, child *ynode) {
	if n.m == nil {
		n.m = map[string]*ynode{}
	}
	if _, seen := n.m[key]; !seen {
		n.keys = append(n.keys, key)
	}
	n.m[key] = child
}

// at returns the child node for key, or nil.
func (n *ynode) at(key string) *ynode {
	if n == nil || n.m == nil {
		return nil
	}
	return n.m[key]
}

// child returns key's node only when it is itself a mapping (has m); nil otherwise.
func (n *ynode) child(key string) *ynode {
	c := n.at(key)
	if c == nil || c.m == nil {
		return nil
	}
	return c
}

// scalarAt returns key's scalar value, or "" when absent / not a scalar.
func (n *ynode) scalarAt(key string) string {
	c := n.at(key)
	if c == nil || !c.isScalar {
		return ""
	}
	return c.scalar
}

// splitYAMLLines normalizes newlines and returns raw physical lines (bounded). Comment/blank
// handling happens during the walk, because block-scalar content must be read verbatim.
func splitYAMLLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > maxYAMLLines {
		lines = lines[:maxYAMLLines]
	}
	return lines
}

// parseYAMLBlock parses the whole document as one block at indent 0.
func parseYAMLBlock(lines []string) *ynode {
	i, budget := 0, maxYAMLNodes
	return parseBlock(lines, &i, 0, &budget)
}

func indentOf(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

func isBlankOrComment(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

// parseBlock parses one container (map or seq) whose lines sit at column `indent`. It advances *i
// past every line it consumes and stops at the first line that dedents below `indent`.
func parseBlock(lines []string, i *int, indent int, budget *int) *ynode {
	node := &ynode{}
	for *i < len(lines) {
		if *budget <= 0 || indent > maxYAMLIndent {
			break
		}
		raw := lines[*i]
		if isBlankOrComment(raw) {
			*i++
			continue
		}
		ind := indentOf(raw)
		if ind < indent {
			break // dedent → this block is done
		}
		if ind > indent {
			*i++ // stray deeper line with no owning key — ignore rather than guess
			continue
		}
		text := stripComment(strings.TrimSpace(raw))
		if text == "-" || strings.HasPrefix(text, "- ") {
			*budget--
			parseSeqItem(lines, i, indent, raw, text, node, budget)
			continue
		}
		*budget--
		if !parseMapEntry(lines, i, indent, text, node, budget) {
			*i++ // unrecognized line — skip
		}
	}
	return node
}

// parseSeqItem handles one `- …` line (and any block it introduces), appending to node.seq.
func parseSeqItem(lines []string, i *int, indent int, raw, text string, node *ynode, budget *int) {
	rest := strings.TrimSpace(text[1:]) // after '-'
	if rest == "" {
		// The item's content is a block on the following, more-indented lines.
		*i++
		ni := peekIndent(lines, *i)
		if ni > indent {
			node.seq = append(node.seq, parseBlock(lines, i, ni, budget))
		} else {
			node.seq = append(node.seq, scalarNode(""))
		}
		return
	}
	if isMapEntry(rest) {
		// Compact sequence-of-mappings: rewrite this line as a map entry at the content column and
		// parse a mapping block there, so aligned sibling keys join the same item and a sibling
		// dash (shallower) ends it.
		afterDash := raw[strings.Index(raw, "-")+1:]
		spaces := len(afterDash) - len(strings.TrimLeft(afterDash, " \t"))
		contentIndent := indent + 1 + spaces
		lines[*i] = strings.Repeat(" ", contentIndent) + rest
		node.seq = append(node.seq, parseBlock(lines, i, contentIndent, budget))
		return
	}
	node.seq = append(node.seq, scalarNode(unquoteScalar(rest)))
	*i++
}

// parseMapEntry handles one `key: …` line, returning false when the line is not a key line.
func parseMapEntry(lines []string, i *int, indent int, text string, node *ynode, budget *int) bool {
	key, val, ok := splitMapLine(text)
	if !ok {
		return false
	}
	if val == "" {
		*i++
		ni := peekIndent(lines, *i)
		if ni > indent {
			node.set(key, parseBlock(lines, i, ni, budget))
		} else {
			node.set(key, scalarNode(""))
		}
		return true
	}
	if c := blockIndicator(val); c != 0 {
		*i++
		content := readBlockScalar(lines, i, indent, c)
		node.set(key, scalarNode(content))
		return true
	}
	if strings.HasPrefix(val, "[") {
		node.set(key, flowSeq(val))
		*i++
		return true
	}
	node.set(key, scalarNode(unquoteScalar(val)))
	*i++
	return true
}

// peekIndent returns the indent of the next structural (non-blank, non-comment) line, or -1 at EOF.
func peekIndent(lines []string, from int) int {
	for j := from; j < len(lines); j++ {
		if isBlankOrComment(lines[j]) {
			continue
		}
		return indentOf(lines[j])
	}
	return -1
}

// readBlockScalar consumes a `|`/`>` block owned by a key at parentIndent and returns its dedented
// text. `fold` ('>' char) joins lines with spaces; literal ('|') keeps newlines. Trailing blank
// lines are trimmed (chomping is not otherwise modeled — a payload skeleton does not need it).
func readBlockScalar(lines []string, i *int, parentIndent int, indicator byte) string {
	blockIndent := -1
	var content []string
	for *i < len(lines) {
		ln := lines[*i]
		if isBlank(ln) {
			content = append(content, "")
			*i++
			continue
		}
		ind := indentOf(ln)
		if ind <= parentIndent {
			break
		}
		if blockIndent == -1 {
			blockIndent = ind
		}
		strip := blockIndent
		if len(ln) < strip {
			strip = len(ln)
		}
		content = append(content, ln[strip:])
		*i++
	}
	for len(content) > 0 && content[len(content)-1] == "" {
		content = content[:len(content)-1]
	}
	if indicator == '>' {
		return strings.Join(content, " ")
	}
	return strings.Join(content, "\n")
}

// isMapEntry reports whether a sequence item's content is itself a mapping (`key: …`) rather than a
// scalar. A quoted item, or one with no `key:`/`key: ` shape, is a scalar (nuclei path items look
// like `- "{{BaseURL}}/x"` and must never be read as maps).
func isMapEntry(s string) bool {
	if s == "" || s[0] == '"' || s[0] == '\'' || s[0] == '[' || s[0] == '{' {
		return false
	}
	_, _, ok := splitMapLine(s)
	return ok
}

// splitMapLine splits `key: value` (or a trailing `key:`) honoring quotes so a value containing a
// colon (a URL, a CVSS vector) is not mistaken for the separator.
func splitMapLine(text string) (key, val string, ok bool) {
	if text == "" {
		return "", "", false
	}
	inSingle, inDouble := false, false
	for idx := 0; idx < len(text); idx++ {
		c := text[idx]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ':' && !inSingle && !inDouble:
			if idx == len(text)-1 { // trailing colon → key opens a child
				return unquoteScalar(strings.TrimSpace(text[:idx])), "", true
			}
			if text[idx+1] == ' ' || text[idx+1] == '\t' {
				return unquoteScalar(strings.TrimSpace(text[:idx])), strings.TrimSpace(text[idx+1:]), true
			}
		}
	}
	return "", "", false
}

// blockIndicator returns '|' or '>' when val is a block-scalar header (with optional chomping/indent
// digits), else 0.
func blockIndicator(val string) byte {
	if val == "" || (val[0] != '|' && val[0] != '>') {
		return 0
	}
	for k := 1; k < len(val); k++ {
		switch val[k] {
		case '-', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		default:
			return 0 // trailing non-indicator text → not a block header (a scalar starting with | or >)
		}
	}
	return val[0]
}

// flowSeq parses a single-level flow sequence `[a, "b", 200]` into a scalar-item seq node.
func flowSeq(val string) *ynode {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "[")
	val = strings.TrimSuffix(val, "]")
	n := &ynode{}
	for _, part := range strings.Split(val, ",") {
		if p := unquoteScalar(strings.TrimSpace(part)); p != "" {
			n.seq = append(n.seq, scalarNode(p))
		}
	}
	return n
}

// stripComment removes an unquoted trailing ` #…` comment.
func stripComment(text string) string {
	inSingle, inDouble := false, false
	for idx := 0; idx < len(text); idx++ {
		c := text[idx]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble && idx > 0 && (text[idx-1] == ' ' || text[idx-1] == '\t'):
			return strings.TrimRight(text[:idx], " \t")
		}
	}
	return text
}

// unquoteScalar strips matching surrounding quotes and applies the minimal escapes nuclei uses.
func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			inner := s[1 : len(s)-1]
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			return inner
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
	}
	return s
}
