package web

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Shape-dedup collapses URLs that differ only in identifier values —
// /items/1, /items/2, … /items/9999 are the same endpoint shape and
// scanning all of them is pure waste (and the main driver of strix's
// hours-long WAVSEP fan-out). We canonicalize id-like path segments to
// placeholders, then keep one URL per (host, canonical-path,
// sorted-query-keys) shape.
//
// Conservative by design: only segments that clearly look like ids
// (pure integers, UUIDs, long hex, dates) collapse. A segment like
// "users" or "search" is content, not an id, and is preserved — so we
// never merge two genuinely-different endpoints.

var (
	reInt  = regexp.MustCompile(`^\d+$`)
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHash = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// canonicalizePath replaces id-like path segments with placeholders so
// /items/42 and /items/99 both canonicalize to /items/:int.
func canonicalizePath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case s == "":
			// keep empty (leading/trailing slash structure)
		case reUUID.MatchString(s):
			segs[i] = ":uuid"
		case reInt.MatchString(s):
			segs[i] = ":int"
		case reDate.MatchString(s):
			segs[i] = ":date"
		case reHash.MatchString(s):
			segs[i] = ":hash"
		}
	}
	return strings.Join(segs, "/")
}

// shapeKey identifies a URL's endpoint shape: host + canonical path +
// sorted query parameter NAMES (values ignored — ?q=a and ?q=b are the
// same shape). Two URLs with the same shapeKey are redundant to scan
// separately.
func shapeKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.ToLower(u.Hostname()) + "|" + canonicalizePath(u.Path) + "|" + strings.Join(keys, ",")
}

// dedupeByShape keeps the first URL seen for each endpoint shape,
// preserving input order (deterministic for reproducibility,
// CLAUDE.md §10).
func dedupeByShape(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		k := shapeKey(u)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, u)
	}
	return out
}
