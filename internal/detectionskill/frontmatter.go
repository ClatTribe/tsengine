package detectionskill

import (
	"errors"
	"strings"
)

// frontmatter.go is a deliberately MINIMAL YAML-subset parser for SKILL.md frontmatter.
//
// Why not a YAML library: yaml is only an indirect dependency here, and the repo's convention is
// dependency-free parsers for small, fixed formats (the .tf resource indexer, the file store, the
// controlxref matrix reader). Frontmatter is a handful of scalars plus two levels of string lists —
// pulling in a full YAML engine to read that would also widen the attack surface of an
// UNTRUSTED-INPUT parser, which is exactly the wrong trade here. Anything this parser does not
// understand is ignored rather than guessed at.
//
// Supported subset:
//
//	name: value                # scalar
//	tags:                      # list of strings
//	  - one
//	  - two
//	matches:                   # map of string lists
//	  rule_ids:
//	    - foo::bar
type frontmatter struct {
	scalars map[string]string
	lists   map[string][]string            // top-level list
	maps    map[string]map[string][]string // top-level map of lists
	keys    []string                       // every top-level key seen, for capability rejection
}

func (f frontmatter) str(k string) string { return strings.TrimSpace(f.scalars[k]) }

func (f frontmatter) list(path ...string) []string {
	switch len(path) {
	case 1:
		return f.lists[path[0]]
	case 2:
		if m, ok := f.maps[path[0]]; ok {
			return m[path[1]]
		}
	}
	return nil
}

// splitFrontmatter separates the leading `---`-delimited block from the markdown body.
// A SKILL.md with no frontmatter is an error: without a name we cannot attribute a verdict to a
// skill, and provenance is non-negotiable (ADR 0017).
func splitFrontmatter(raw []byte) (frontmatter, string, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.HasPrefix(strings.TrimSpace(text), "---") {
		return frontmatter{}, "", errors.New("SKILL.md must begin with a `---` frontmatter block")
	}
	text = strings.TrimSpace(text)
	rest := strings.TrimPrefix(text, "---")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return frontmatter{}, "", errors.New("SKILL.md frontmatter block is not closed with `---`")
	}
	fmText := rest[:end]
	body := strings.TrimPrefix(rest[end+len("\n---"):], "\n")
	return parseFrontmatter(fmText), body, nil
}

func parseFrontmatter(s string) frontmatter {
	f := frontmatter{
		scalars: map[string]string{},
		lists:   map[string][]string{},
		maps:    map[string]map[string][]string{},
	}
	var curTop, curSub string

	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimRight(raw, " \t")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		t := strings.TrimSpace(line)

		// A list item belongs to the most recent key at its level.
		if strings.HasPrefix(t, "- ") {
			item := unquote(strings.TrimSpace(strings.TrimPrefix(t, "- ")))
			if item == "" {
				continue
			}
			if curSub != "" && curTop != "" {
				f.maps[curTop][curSub] = append(f.maps[curTop][curSub], item)
			} else if curTop != "" {
				f.lists[curTop] = append(f.lists[curTop], item)
			}
			continue
		}

		key, val, ok := strings.Cut(t, ":")
		if !ok {
			continue // not a key line — ignore rather than guess
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if indent == 0 {
			curTop, curSub = key, ""
			f.keys = append(f.keys, key)
			if val != "" {
				f.scalars[key] = unquote(val)
				curTop = "" // a scalar cannot own following list items
			} else {
				// A bare `key:` may open either a list or a map; allocate both lazily.
				if _, exists := f.maps[key]; !exists {
					f.maps[key] = map[string][]string{}
				}
			}
			continue
		}
		// Indented `key:` → a sub-key of the current top-level map.
		if curTop != "" {
			curSub = key
			if val != "" {
				// `matches: {rule_ids: x}` style scalar — treat as a one-item list.
				f.maps[curTop][key] = append(f.maps[curTop][key], unquote(val))
				curSub = ""
			}
		}
	}
	return f
}

// unquote strips matching surrounding quotes, if present.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
