package estateingest

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// LeadsForRoutes turns the estate graph into the pentester's "what does this route reach?" context.
//
// This is the delivery end of the whole substrate for the offensive agent. The graph knows that a web
// host sits on a path to a PII table or an admin identity; the pentester, handed a flat list of URLs,
// does not. A lead closes that gap so the agent spends its request budget by STAKES rather than by the
// shape of the URL — the web-agent twin of the cloud agent's Bridges.
//
// GROUNDED (§10), end to end. Every lead is a REAL path the graph holds, and the graph refuses edges
// that cite no evidence — so a lead can only describe a route the estate actually proves reaches a
// crown jewel. The lead widens where the agent LOOKS; it never stands in for proof, and the pentester's
// deterministic indicators still dispose (a finding needs its indicator regardless of any lead).
//
// routes are the agent's known request surface; the returned leads are keyed to whichever route a web
// host node corresponds to, so the agent can line a lead up against a URL it will actually probe.
func LeadsForRoutes(g *estategraph.Graph, routes []string) []webagent.EstateLead {
	if g == nil || len(routes) == 0 {
		return nil
	}
	// Index the graph's web-host nodes by their canonical id, so a route matches the node the cloud/web
	// surface asserted.
	var leads []webagent.EstateLead
	seen := map[string]bool{}

	for _, route := range routes {
		hostID := estategraph.Canonical(SurfaceCode, route) // http(s) → host: namespace, shared across surfaces
		if !strings.HasPrefix(hostID, "host:") {
			// A route that does not canonicalise to a host (a bare path, say) has no node to anchor on.
			continue
		}
		if seen[hostID] || g.Nodes[hostID] == nil {
			continue // unknown to the graph, or already covered by an earlier route form
		}
		paths, _ := g.PathsFrom(hostID, estategraph.Crown, 6, 8)
		if len(paths) == 0 {
			continue // this host reaches no crown jewel — no lead to give
		}
		seen[hostID] = true

		// The single strongest path is what the agent needs — the crown it reaches and the one-line
		// chain. More than one would bury the signal the lead exists to surface.
		best := strongest(g, paths)
		crown := g.Nodes[best.Nodes[len(best.Nodes)-1]]
		leads = append(leads, webagent.EstateLead{
			Route:    route,
			Reaches:  describeCrown(crown),
			Why:      chainSentence(g, best),
			Evidence: pathEvidence(best),
		})
	}
	return leads
}

// strongest picks the path whose endpoint is the most valuable, then the shortest — a sensitive-data
// crown two hops away is a sharper lead than a privileged identity five hops away.
func strongest(g *estategraph.Graph, paths []estategraph.Path) estategraph.Path {
	best := paths[0]
	bestScore := pathScore(g, best)
	for _, p := range paths[1:] {
		if s := pathScore(g, p); s > bestScore {
			best, bestScore = p, s
		}
	}
	return best
}

func pathScore(g *estategraph.Graph, p estategraph.Path) int {
	if len(p.Nodes) == 0 {
		return 0
	}
	end := g.Nodes[p.Nodes[len(p.Nodes)-1]]
	score := 0
	if end != nil {
		if end.Sensitive == estategraph.SensHigh {
			score += 100 // data at rest is the sharpest stake
		}
		if end.Privileged {
			score += 60
		}
	}
	score -= len(p.Edges) // shorter chains are more actionable
	return score
}

// describeCrown states, in the pentester's terms, why the endpoint is worth reaching.
func describeCrown(n *estategraph.Node) string {
	if n == nil {
		return "a high-value asset"
	}
	name := n.Name
	if name == "" {
		name = n.ID
	}
	switch {
	case n.Sensitive == estategraph.SensHigh && n.Privileged:
		return "a privileged identity that can read regulated data (" + name + ")"
	case n.Sensitive == estategraph.SensHigh:
		return "regulated data (" + name + ")"
	case n.Privileged:
		return "a privileged identity (" + name + ")"
	default:
		return name
	}
}

// chainSentence renders the route→crown path as one readable line, naming the moves. It is the "why
// this route matters" the agent reasons over — never a substitute for the indicator that grounds a
// finding.
func chainSentence(g *estategraph.Graph, p estategraph.Path) string {
	if len(p.Edges) == 0 {
		return ""
	}
	var parts []string
	for _, e := range p.Edges {
		parts = append(parts, nodeLabel(g, e.From)+" "+moveVerb(e.Kind)+" "+nodeLabel(g, e.To))
	}
	return strings.Join(parts, ", then ")
}

func nodeLabel(g *estategraph.Graph, id string) string {
	if n := g.Nodes[id]; n != nil && n.Name != "" {
		return n.Name
	}
	// Strip the namespace prefix for readability (host:, principal:, secret:).
	if i := strings.Index(id, ":"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func moveVerb(k estategraph.EdgeKind) string {
	switch k {
	case estategraph.EdgeReaches:
		return "reaches"
	case estategraph.EdgeGrants:
		return "can access"
	case estategraph.EdgeAssumes:
		return "becomes"
	case estategraph.EdgeRunsAs:
		return "runs as"
	case estategraph.EdgeLeakedIn:
		return "is exposed in"
	case estategraph.EdgeStores:
		return "holds the data in"
	case estategraph.EdgeOwns:
		return "administers"
	default:
		return "→"
	}
}

// pathEvidence collects the distinct proof refs along the path, so a lead is auditable.
func pathEvidence(p estategraph.Path) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range p.Edges {
		for _, ev := range e.Evidence {
			if !seen[ev] {
				seen[ev] = true
				out = append(out, ev)
			}
		}
	}
	return out
}
