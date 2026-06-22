// Package postman imports a Postman collection (v2.x) into the api asset's endpoint inventory —
// the must-have api integration for the many SMB teams whose API surface lives in Postman, not a
// served OpenAPI spec. It's the Postman analogue of internal/tool/openapi: a pure-Go (no binary)
// parser that flattens a collection's (recursively nested) requests into the same "METHOD url"
// operation entries the api PlanFanout fans detection across.
//
// Grounded + deterministic: only requests actually present in the collection become endpoints,
// collection-level {{variables}} are resolved from the collection's own variable list, and the
// output is sorted. Unresolvable variables (e.g. those that live in a separate Postman environment)
// are left intact — the operation is still recorded, never guessed.
package postman

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Collection is the imported result: the collection name + its flattened operation inventory.
type Collection struct {
	Name       string   `json:"name"`
	Operations []string `json:"operations"` // "METHOD url", openapi-compatible
}

// raw mirrors the slice of the Postman collection v2.x schema we read.
type raw struct {
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
	Item     []item    `json:"item"`
	Variable []kvValue `json:"variable"`
}

type kvValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// item is either a folder (has Item children) or a request leaf (has Request).
type item struct {
	Name    string          `json:"name"`
	Item    []item          `json:"item"`
	Request json.RawMessage `json:"request"`
}

type request struct {
	Method string          `json:"method"`
	URL    json.RawMessage `json:"url"` // string OR {raw, host, path}
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// Endpoints parses a Postman collection JSON into its operation inventory. Returns an error only
// when the bytes aren't a parseable collection; an empty (but valid) collection yields zero
// operations, never an error.
func Endpoints(collection []byte) (Collection, error) {
	var r raw
	if err := json.Unmarshal(collection, &r); err != nil {
		return Collection{}, fmt.Errorf("postman: parse collection: %w", err)
	}
	if r.Item == nil && r.Info.Name == "" {
		return Collection{}, fmt.Errorf("postman: not a collection (no info/item)")
	}
	vars := map[string]string{}
	for _, v := range r.Variable {
		if v.Key != "" {
			vars[v.Key] = v.Value
		}
	}
	seen := map[string]bool{}
	var ops []string
	var walk func(items []item)
	walk = func(items []item) {
		for _, it := range items {
			if len(it.Item) > 0 {
				walk(it.Item) // folder → recurse
			}
			if len(it.Request) == 0 {
				continue
			}
			if op, ok := operation(it.Request, vars); ok && !seen[op] {
				seen[op] = true
				ops = append(ops, op)
			}
		}
	}
	walk(r.Item)
	sort.Strings(ops)
	return Collection{Name: r.Info.Name, Operations: ops}, nil
}

// operation extracts "METHOD url" from a request, resolving {{vars}} and stripping the query.
func operation(rawReq json.RawMessage, vars map[string]string) (string, bool) {
	var req request
	if json.Unmarshal(rawReq, &req) != nil {
		return "", false
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if !httpMethods[method] {
		return "", false
	}
	u := resolveURL(req.URL, vars)
	if u == "" {
		return "", false
	}
	if i := strings.IndexByte(u, '?'); i >= 0 { // drop the query — the scanner re-parameterizes
		u = u[:i]
	}
	return method + " " + strings.TrimRight(u, "/"), true
}

// resolveURL reads a Postman url (string or {raw|host+path}) and substitutes {{variables}}.
func resolveURL(rawURL json.RawMessage, vars map[string]string) string {
	if len(rawURL) == 0 {
		return ""
	}
	// Form 1: a bare string URL.
	var s string
	if json.Unmarshal(rawURL, &s) == nil {
		return subst(s, vars)
	}
	// Form 2: an object {raw, host[], path[]}.
	var obj struct {
		Raw  string   `json:"raw"`
		Host []string `json:"host"`
		Path []string `json:"path"`
	}
	if json.Unmarshal(rawURL, &obj) != nil {
		return ""
	}
	if obj.Raw != "" {
		return subst(obj.Raw, vars)
	}
	if len(obj.Host) > 0 {
		u := strings.Join(obj.Host, ".")
		if len(obj.Path) > 0 {
			u += "/" + strings.Join(obj.Path, "/")
		}
		return subst(u, vars)
	}
	return ""
}

// subst replaces {{key}} with the variable's value (single pass; unknown vars left intact).
func subst(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return strings.TrimSpace(s)
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return strings.TrimSpace(s)
}
