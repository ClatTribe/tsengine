package fleet

import (
	"fmt"
	"sort"
	"strings"
)

// Ledger renders the per-route×class coverage the engagement established, plus the routes that were
// KNOWN but yielded no verdict — the "untried" set. This is the deepening of #1444's run-level
// Report.Coverage into a finding-granularity artifact: "probed 40/50 routes" becomes "route /search:
// sqli vulnerable (2 turns); route /admin: known, no verdict established".
//
// Honest by construction (§10): a known route with no proven class is reported as "no verdict
// established", NEVER as clean — Phase A cannot ground a Clean (that needs a chunk's attempt scope,
// Phase B), so it does not claim one. The distinction between "tested and clean" and "never tried" is
// exactly what this ledger refuses to blur.
func (r *Result) Ledger() string {
	if r == nil || r.Worldview == nil {
		return "no worldview"
	}
	byRoute := map[string][]ClassVerdict{}
	for _, v := range r.Worldview.Verdicts() {
		byRoute[v.Route] = append(byRoute[v.Route], v)
	}

	var b strings.Builder
	counts := r.Worldview.Counts()
	fmt.Fprintf(&b, "worldview: %d route×class verdict(s) over %d known route(s)\n",
		len(r.Worldview.Verdicts()), len(r.KnownRoutes))
	if n := counts[Contested]; n > 0 {
		fmt.Fprintf(&b, "  ⚠ %d contested (independent looks disagreed — unresolved, needs adjudication)\n", n)
	}

	// Established routes first, sorted, each with its per-class verdicts.
	established := sortedKeys(byRoute)
	for _, route := range established {
		fmt.Fprintf(&b, "  %s\n", route)
		vs := byRoute[route]
		sort.Slice(vs, func(i, j int) bool { return vs[i].Class < vs[j].Class })
		for _, v := range vs {
			fmt.Fprintf(&b, "    - %s: %s (%d turn%s of evidence)\n",
				v.Class, v.Verdict, len(v.Evidence), plural(len(v.Evidence)))
		}
	}

	// Known-but-no-verdict routes: named explicitly so an empty finding on a route is not read as
	// "we looked and it was fine".
	var untried []string
	for _, route := range r.KnownRoutes {
		if _, ok := byRoute[route]; !ok {
			untried = append(untried, route)
		}
	}
	if len(untried) > 0 {
		fmt.Fprintf(&b, "  %d known route(s) with NO established verdict (not proven, not cleared — untried or inconclusive):\n", len(untried))
		for _, route := range untried {
			fmt.Fprintf(&b, "    · %s\n", route)
		}
	}
	return b.String()
}

func sortedKeys(m map[string][]ClassVerdict) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
