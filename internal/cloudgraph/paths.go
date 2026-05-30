package cloudgraph

import "sort"

// Path is a discovered chain from a source node to a target node — the raw
// material of an attack-path finding. Nodes[0] is the source; each Edges[i]
// goes Nodes[i] → Nodes[i+1].
type Path struct {
	Nodes []string `json:"nodes"`
	Edges []Edge   `json:"edges"`
}

// TargetFunc matches a destination node (e.g. "a sensitive data store", "an
// admin principal").
type TargetFunc func(*Node) bool

// FindPaths returns simple paths (no repeated node) from `from` to any node
// matching `target`, traversing only edges whose kind is allowed (nil allow =
// all kinds). It is the deterministic discovery engine the engineer reasons
// with — zero live touch.
//
// Bounded for termination + cost (CLAUDE.md §5.3 / the design doc's efficiency
// model): maxDepth caps path length, maxPaths caps the result set. Traversal is
// deterministic (edges + neighbours sorted), so the same snapshot yields the
// same paths (reproducibility, §10).
func (s *Snapshot) FindPaths(from string, target TargetFunc, allow map[EdgeKind]bool, maxDepth, maxPaths int) []Path {
	if s.Nodes[from] == nil || target == nil {
		return nil
	}
	if maxDepth <= 0 {
		maxDepth = 8
	}
	if maxPaths <= 0 {
		maxPaths = 50
	}

	var out []Path
	onPath := map[string]bool{from: true}
	curNodes := []string{from}
	var curEdges []Edge

	var dfs func(node string, depth int)
	dfs = func(node string, depth int) {
		if len(out) >= maxPaths || depth >= maxDepth {
			return
		}
		edges := append([]Edge(nil), s.edgesFrom(node)...)
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].To != edges[j].To {
				return edges[i].To < edges[j].To
			}
			return edges[i].Kind < edges[j].Kind
		})
		for _, e := range edges {
			if allow != nil && !allow[e.Kind] {
				continue
			}
			nxt := s.Nodes[e.To]
			if nxt == nil || onPath[e.To] {
				continue
			}
			curNodes = append(curNodes, e.To)
			curEdges = append(curEdges, e)
			onPath[e.To] = true

			if target(nxt) {
				out = append(out, Path{
					Nodes: append([]string(nil), curNodes...),
					Edges: append([]Edge(nil), curEdges...),
				})
			}
			dfs(e.To, depth+1)

			onPath[e.To] = false
			curNodes = curNodes[:len(curNodes)-1]
			curEdges = curEdges[:len(curEdges)-1]
			if len(out) >= maxPaths {
				return
			}
		}
	}
	dfs(from, 0)
	return out
}

// Conditional reports whether any edge on the path carries a runtime condition —
// i.e. the path is config-possible but may be blocked at runtime, so it warrants
// live validation before being called real-impact (ADR 0002).
func (p Path) Conditional() bool {
	for _, e := range p.Edges {
		if e.Condition != "" {
			return true
		}
	}
	return false
}

// --- common target predicates -------------------------------------------------

// SensitiveData matches a node holding high-sensitivity data.
func SensitiveData(n *Node) bool { return n != nil && n.Sensitive == SensHigh }

// PrivilegedIdentity matches a high-privilege principal.
func PrivilegedIdentity(n *Node) bool { return n != nil && n.Privileged }

// AllAttackEdges is the default edge allow-set for attack-path discovery.
var AllAttackEdges = map[EdgeKind]bool{
	EdgeAssumeRole: true, EdgePassRole: true, EdgeHasAccess: true,
	EdgeNetworkReach: true, EdgeRunsAs: true, EdgePrivesc: true,
}
