package crossdetect

import (
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// runtime.go is the Runtime Protection correlation (ADR-0007 Phase 0). It joins
// in-app-firewall / RASP attack events to unified issues by endpoint, so a finding
// on a route that is ALSO being attacked in production is flagged
// observed-in-the-wild — the strongest exploitability signal there is.
//
// Orchestration glue only: it adds NO detection (the scanner found the weakness, the
// sensor observed the attack); it correlates two real signals on a concrete shared
// key (the endpoint path), never a guessed link (§10/§13).

// AnnotateRuntime marks each issue that shares an endpoint with ≥1 runtime attack
// event, setting Attacked + AttackCount. Issues without an endpoint (e.g. dependency
// CVEs) never match — a route attack isn't evidence about a package. Returns the
// annotated issues (in place) and the number that were flagged.
func AnnotateRuntime(issues []Issue, events []platform.RuntimeEvent) int {
	if len(events) == 0 {
		return 0
	}
	// Bucket attack counts by endpoint path.
	byPath := map[string]int{}
	for _, e := range events {
		if p := httpPath(e.Endpoint); p != "" {
			byPath[p]++
		}
	}
	flagged := 0
	for i := range issues {
		p := httpPath(issues[i].Endpoint)
		if p == "" {
			continue
		}
		if n := byPath[p]; n > 0 {
			issues[i].Attacked = true
			issues[i].AttackCount = n
			flagged++
		}
	}
	return flagged
}

// httpPath normalizes a URL or route to its host-less path ("/search"), lower-cased,
// without scheme / host / query / trailing slash. Returns "" when there is no path
// component (so non-HTTP endpoints — a package coordinate, a bare host — never match).
func httpPath(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	i := strings.Index(s, "/")
	if i < 0 {
		return "" // no path segment (a bare host, or a package coordinate)
	}
	s = strings.TrimRight(s[i:], "/")
	if s == "" {
		return "/"
	}
	return s
}
