package reachability

// lex.go holds the tiny, dependency-free lexing helpers the non-Go extractors share.
// The core trick: blank out comment + string-literal CONTENT (replacing each byte with a
// space, preserving length + newlines) BEFORE regex/brace scanning, so a `require(`,
// `import`, or `{` inside a string/comment can never produce a false edge. Positions are
// preserved 1:1, so spans computed on the blanked view map back onto the raw source.

// blankLiterals blanks C-style // and /* */ comments and ' " ` string literals (JS/TS).
func blankLiterals(src string) string {
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
		case c == '/' && i+1 < n && b[i+1] == '/':
			for i < n && b[i] != '\n' {
				blank(i)
				i++
			}
		case c == '/' && i+1 < n && b[i+1] == '*':
			blank(i)
			i++
			for i < n {
				if b[i] == '*' && i+1 < n && b[i+1] == '/' {
					blank(i)
					blank(i + 1)
					i += 2
					break
				}
				blank(i)
				i++
			}
		case c == '\'' || c == '"' || c == '`':
			quote := c
			blank(i) // opening quote
			i++
			for i < n {
				if b[i] == '\\' { // escape — skip next
					blank(i)
					if i+1 < n {
						blank(i + 1)
					}
					i += 2
					continue
				}
				if b[i] == quote {
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

// blankComments blanks ONLY C-style // and /* */ comments, PRESERVING string literals —
// used for import parsing, where the package spec IS a string ('lodash') that must survive,
// while a `require()` inside a comment must not match. String-borne false imports are
// rejected separately by the line-start anchor on the import regexes.
func blankComments(src string) string {
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
		case c == '/' && i+1 < n && b[i+1] == '/':
			for i < n && b[i] != '\n' {
				blank(i)
				i++
			}
		case c == '/' && i+1 < n && b[i+1] == '*':
			blank(i)
			blank(i + 1)
			i += 2
			for i < n {
				if b[i] == '*' && i+1 < n && b[i+1] == '/' {
					blank(i)
					blank(i + 1)
					i += 2
					break
				}
				blank(i)
				i++
			}
		case c == '\'' || c == '"' || c == '`':
			// skip over the string literal untouched (preserve its content).
			q := c
			i++
			for i < n {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == q {
					i++
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// matchBrace returns the index just past the '}' matching the '{' at openPos, or -1.
// Runs on already-blanked source, so braces inside literals are spaces and can't skew the
// count.
func matchBrace(src string, openPos int) int {
	depth := 0
	for i := openPos; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// precededByWord reports whether the token immediately before pos (skipping spaces/tabs)
// is exactly `word` — used to tell a call site `foo(` apart from a declaration header
// `function foo(` / `def foo(`, which must NOT be counted as a call (a false edge that
// would make a private, never-invoked function look reachable).
func precededByWord(src string, pos int, word string) bool {
	i := pos - 1
	for i >= 0 && (src[i] == ' ' || src[i] == '\t' || src[i] == '*') {
		i--
	}
	end := i + 1
	for i >= 0 && (isWordByte(src[i])) {
		i--
	}
	return src[i+1:end] == word
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// splitTopLevelCommas splits on commas that are not nested inside (), [], or {}.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}
