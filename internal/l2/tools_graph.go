package l2

import (
	"context"
	"fmt"
	"strings"
)

// tools_graph.go lets the Lead WALK the estate instead of reading a summary of it.
//
// THE GAP. EstateContext.AttackPaths is []string — its own comment says "pre-rendered chain
// summaries". The engineer is handed paragraphs someone else wrote about the graph and cannot ask the
// three questions the job actually turns on: what else touches this node, where does this lead, and
// what is the ONE thing that cuts the most paths. Meanwhile cloudagent walks a real typed graph, and
// cross-surface knowledge reaches it through cloudagent.Context.Bridges []string — a hand-built
// channel for smuggling graph facts in as text, which is the clearest evidence that prose was never
// the right interface.
//
// ONE SLOT, FOUR OPERATIONS (§2.6). The ≤12 cap is a capability constraint, not bureaucracy, and four
// separate traversal tools would eat a third of the belt. So this mirrors dispatch_l2_probe: a single
// catalogue slot that reaches several operations, keeping the model's visible list small while its
// reach grows. Phase-scoped to Investigate and Chain — traversal is how you build a chain, and it is
// noise during triage.
//
// GROUNDED (§10). The traversal returns what the graph HOLDS, and the graph refuses edges that cite no
// evidence (estategraph.AddEdge → ErrNoEvidence). So the model cannot be handed a hop nobody proved,
// and every rendered hop carries its evidence refs — the agent cites the graph's proof rather than its
// own recollection. Unwired, the tool says so plainly instead of implying an empty estate.

// GraphHop is one proven move, flattened for rendering. Plain data by design: l2 stays engine-pure
// (it imports only pkg/types), so the platform adapter converts from estategraph rather than l2
// importing it.
type GraphHop struct {
	From     string
	To       string
	Kind     string
	Why      string
	Evidence []string
}

// GraphPath is a route through the estate.
type GraphPath struct {
	Nodes []string
	Hops  []GraphHop
}

// GraphChokePoint is one node many paths run through.
type GraphChokePoint struct {
	ID    string
	Name  string
	Paths int
	Why   string
}

// EstateGraph is the traversal surface the Lead reasons over.
//
// Every method answers from the graph's own contents. Truncated is reported rather than swallowed: a
// bounded answer presented as complete is how an agent concludes "there is no other route" from a
// result that simply stopped early.
type EstateGraph interface {
	// Neighbors returns what is one hop from a node, with the move that gets there.
	Neighbors(ctx context.Context, node string) ([]GraphHop, error)
	// PathsFrom returns routes from a node to anything worth reaching.
	PathsFrom(ctx context.Context, node string) (paths []GraphPath, truncated bool, err error)
	// Why returns the evidence behind a specific move.
	Why(ctx context.Context, from, to string) ([]GraphHop, error)
	// ChokePoints ranks the nodes that cut the most paths.
	ChokePoints(ctx context.Context) ([]GraphChokePoint, error)
}

// GraphTools returns the traversal slot. Nil source → an empty catalog, so a deployment without a
// graph does not spend cap on a tool that can only answer "not available".
func GraphTools(g EstateGraph) Catalog {
	if g == nil {
		return nil
	}
	return Catalog{{
		Schema: ToolSchema{
			Name: "traverse_estate",
			Description: "Walk the estate graph — the cross-surface map of what reaches what, where " +
				"every connection is backed by evidence. Operations: 'neighbors' (what is one hop from " +
				"a node), 'paths_from' (where a node leads, ending at sensitive data or privileged " +
				"identities), 'why' (the evidence behind one specific connection — use it before " +
				"claiming a link is real), 'chokepoints' (the single nodes that cut the most attack " +
				"paths, i.e. what to fix first). Use this to build attack chains instead of guessing " +
				"which findings relate.",
			Params: obj(map[string]any{
				"op":   str("neighbors | paths_from | why | chokepoints"),
				"node": str("the node id to start from (required for neighbors, paths_from, why)"),
				"to":   str("the destination node id (required for why)"),
			}, "op"),
		},
		Phases: []Phase{PhaseInvestigate, PhaseChain},
		// EXACT, not cumulative: by the report phase the chain is already built, so traversal there
		// would only inflate the terminal phase — which sits at the §2.6 cap — for no capability gain.
		OnlyInPhases: true,
		Handler: func(ctx context.Context, args map[string]any, _ *State) (ToolResult, error) {
			op := strings.ToLower(strings.TrimSpace(engArg(args, "op")))
			node := engArg(args, "node")

			switch op {
			case "chokepoints":
				cps, err := g.ChokePoints(ctx)
				if err != nil {
					return ToolResult{Content: "Traversal failed: " + err.Error()}, nil
				}
				return ToolResult{Content: renderChokePoints(cps)}, nil

			case "neighbors":
				if node == "" {
					return ToolResult{Content: "neighbors needs a node."}, nil
				}
				hops, err := g.Neighbors(ctx, node)
				if err != nil {
					return ToolResult{Content: "Traversal failed: " + err.Error()}, nil
				}
				if len(hops) == 0 {
					// Deliberately not "nothing is connected": an absent node and an isolated one are
					// different facts, and only one of them means the estate is clean here.
					return ToolResult{Content: "Nothing in the graph reaches out from " + node +
						". That means no PROVEN connection is recorded — either it is genuinely isolated, " +
						"or the surface that would prove a link has not been ingested."}, nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%d proven move(s) out of %s:\n", len(hops), node)
				writeHops(&b, hops)
				return ToolResult{Content: b.String()}, nil

			case "paths_from":
				if node == "" {
					return ToolResult{Content: "paths_from needs a node."}, nil
				}
				paths, truncated, err := g.PathsFrom(ctx, node)
				if err != nil {
					return ToolResult{Content: "Traversal failed: " + err.Error()}, nil
				}
				if len(paths) == 0 {
					return ToolResult{Content: "No proven path from " + node + " reaches sensitive data " +
						"or a privileged identity. This is not proof that none exists — only that none is " +
						"recorded in the graph."}, nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%d path(s) from %s:\n", len(paths), node)
				for i, p := range paths {
					fmt.Fprintf(&b, "\nPath %d: %s\n", i+1, strings.Join(p.Nodes, " → "))
					writeHops(&b, p.Hops)
				}
				if truncated {
					// The agent must know the list stopped early, or it will reason as though it has
					// seen every route and rule out the one it never got.
					b.WriteString("\n(TRUNCATED — the search hit its bound, so there may be further paths " +
						"you have not seen. Do not conclude this is the complete set.)\n")
				}
				return ToolResult{Content: b.String()}, nil

			case "why":
				to := engArg(args, "to")
				if node == "" || to == "" {
					return ToolResult{Content: "why needs both 'node' and 'to'."}, nil
				}
				hops, err := g.Why(ctx, node, to)
				if err != nil {
					return ToolResult{Content: "Traversal failed: " + err.Error()}, nil
				}
				if len(hops) == 0 {
					return ToolResult{Content: "No proven connection from " + node + " to " + to +
						" is recorded. Do not report a link between them."}, nil
				}
				var b strings.Builder
				fmt.Fprintf(&b, "Proven connection(s) from %s to %s:\n", node, to)
				writeHops(&b, hops)
				return ToolResult{Content: b.String()}, nil
			}
			return ToolResult{Content: "traverse_estate: unknown op " + engArg(args, "op") +
				" (want neighbors, paths_from, why, or chokepoints)."}, nil
		},
	}}
}

// writeHops renders moves WITH their evidence. The evidence is the point: it is what the agent cites
// when it reports a chain, so a report can be traced back to the observation rather than to the
// model's say-so.
func writeHops(b *strings.Builder, hops []GraphHop) {
	for _, h := range hops {
		fmt.Fprintf(b, "  - %s --[%s]--> %s", h.From, h.Kind, h.To)
		if h.Why != "" {
			b.WriteString("  (" + h.Why + ")")
		}
		if len(h.Evidence) > 0 {
			b.WriteString("  [evidence: " + strings.Join(h.Evidence, ", ") + "]")
		}
		b.WriteByte('\n')
	}
}

func renderChokePoints(cps []GraphChokePoint) string {
	if len(cps) == 0 {
		// A real answer, not a failure: it means each path is genuinely separate work. Saying so beats
		// promoting the least-unshared node to look decisive.
		return "No choke point: no single node appears in more than one attack path, so each path is " +
			"separate work. There is no one fix that collapses several here."
	}
	var b strings.Builder
	b.WriteString("Highest-leverage nodes (cutting one severs every path through it):\n")
	for _, c := range cps {
		name := c.Name
		if name == "" {
			name = c.ID
		}
		fmt.Fprintf(&b, "  - %s (%s) — in %d paths. %s\n", name, c.ID, c.Paths, c.Why)
	}
	return b.String()
}
