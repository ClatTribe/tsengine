package platformapi

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/l2"
)

// estate_graph_adapter.go completes ADR 0032 D6's wiring half: the L2 Lead's
// traverse_estate tool has had a slot (`l2.Deps.Graph`) and a stage-gated catalog
// entry since it shipped, but nothing implemented `l2.EstateGraph` over the
// composed graph — so the tool was built-but-unreachable (PR #1444 note). This
// adapter is that implementation: every answer comes from the graph's own
// contents, every hop carries its evidence refs, and truncation is REPORTED
// rather than swallowed.

// estateGraphAdapter adapts *estategraph.Graph to l2.EstateGraph.
type estateGraphAdapter struct{ g *estategraph.Graph }

func newEstateGraphAdapter(g *estategraph.Graph) *estateGraphAdapter {
	if g == nil || len(g.Nodes) == 0 {
		return nil
	}
	return &estateGraphAdapter{g: g}
}

func hopFromEdge(e estategraph.Edge) l2.GraphHop {
	return l2.GraphHop{
		From: e.From, To: e.To, Kind: string(e.Kind), Why: e.Why, Evidence: e.Evidence,
	}
}

func (a *estateGraphAdapter) Neighbors(_ context.Context, node string) ([]l2.GraphHop, error) {
	if _, ok := a.g.Nodes[node]; !ok {
		return nil, fmt.Errorf("unknown node %q", node)
	}
	hops := []l2.GraphHop{}
	for _, e := range a.g.Out(node) {
		hops = append(hops, hopFromEdge(e))
	}
	for _, e := range a.g.In(node) {
		h := hopFromEdge(e)
		h.From, h.To = e.To, e.From // inbound moves render from the queried node outward
		hops = append(hops, h)
	}
	return hops, nil
}

func (a *estateGraphAdapter) PathsFrom(_ context.Context, node string) ([]l2.GraphPath, bool, error) {
	if _, ok := a.g.Nodes[node]; !ok {
		return nil, false, fmt.Errorf("unknown node %q", node)
	}
	want := func(n *estategraph.Node) bool { return estategraph.Crown(n) }
	paths, truncated := a.g.PathsFrom(node, want, 6, 50)
	out := make([]l2.GraphPath, 0, len(paths))
	for _, p := range paths {
		gp := l2.GraphPath{Nodes: p.Nodes}
		for _, e := range p.Edges {
			gp.Hops = append(gp.Hops, hopFromEdge(e))
		}
		out = append(out, gp)
	}
	return out, truncated, nil
}

func (a *estateGraphAdapter) Why(_ context.Context, from, to string) ([]l2.GraphHop, error) {
	hops := []l2.GraphHop{}
	for _, e := range a.g.Out(from) {
		if e.To == to {
			hops = append(hops, hopFromEdge(e))
		}
	}
	return hops, nil
}

func (a *estateGraphAdapter) ChokePoints(_ context.Context) ([]l2.GraphChokePoint, error) {
	cps := []l2.GraphChokePoint{}
	all, _ := a.allCrownPaths()
	for _, cp := range estategraph.ChokePoints(all) {
		name := ""
		if n, ok := a.g.Nodes[cp.ID]; ok {
			name = n.Name
		}
		cps = append(cps, l2.GraphChokePoint{ID: cp.ID, Name: name, Paths: cp.Paths})
	}
	return cps, nil
}

// allCrownPaths enumerates crown-bound paths from every public or privileged start —
// the same enumeration ChokePoints summarises.
func (a *estateGraphAdapter) allCrownPaths() ([]estategraph.Path, bool) {
	var out []estategraph.Path
	truncated := false
	for id := range a.g.Nodes {
		n := a.g.Nodes[id]
		if !n.Public && !n.Privileged {
			continue
		}
		paths, t := a.g.PathsFrom(id, func(x *estategraph.Node) bool { return estategraph.Crown(x) }, 6, 25)
		out = append(out, paths...)
		truncated = truncated || t
	}
	return out, truncated
}
