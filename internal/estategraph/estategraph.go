// Package estategraph is the CROSS-SURFACE ESTATE GRAPH — the substrate the AI Security Engineer and
// AI Pentester are supposed to be downstream of.
//
// WHY THIS EXISTS. Today the engine has a real typed graph for exactly one surface: cloudgraph, which
// the cloud agent walks. Every other surface — code, SaaS, identity, OSINT, TPRM, devices, the data
// warehouse — is a flat []types.Finding, and cross-surface reasoning happens in crossdetect.Correlate,
// which rebuilds an ephemeral node set on every call by regex-matching entity strings and renders the
// result to prose. The Lead then reads that prose (l2.Estate.AttackPaths is []string). So the engineer
// cannot traverse an edge, pivot to a neighbour, or ask what else touches a node; and the pentester,
// which receives only a target and seed routes, has no estate awareness at all.
//
// The tell that the shape is wrong is cloudagent.Context.Bridges []string: a hand-built channel for
// smuggling cross-surface knowledge into the one agent that has a graph, AS STRINGS. Every new
// cross-surface capability has had to invent its own bypass because there is no shared substrate.
//
// THE THREE AGENT JOBS ARE ALL GRAPH OPERATIONS — discovery extends nodes and edges, a pentest walks a
// path and proves it, a remediation cuts an edge. On a findings list each one re-derives the graph from
// strings and none of them can share what it learned.
//
// # What makes this ours rather than a generic graph
//
// AN EDGE THAT CANNOT CITE EVIDENCE CANNOT EXIST. AddEdge REFUSES it (ErrNoEvidence). §10 is enforced
// structurally here rather than by convention, and the reason is specific: an LLM agent traversing this
// graph must not be able to walk a hop nobody proved. The graph is the agent's ground truth, so an
// unproven edge in it is a hallucination with a data structure around it.
//
// IDENTITY RESOLUTION IS EXACT, NEVER FUZZY. The whole value is that a warehouse grantee
// (etl@acme.iam.gserviceaccount.com) is the SAME node as the GCP service account in the cloud
// inventory. Canonical() normalises known identifier shapes so two surfaces asserting the same
// real-world thing converge on one id. It will not merge on resemblance: a wrong merge invents a path
// that does not exist, which is worse than the two disconnected subgraphs we have today.
//
// # Strangler, not big-bang
//
// This lands ALONGSIDE crossdetect, which keeps working untouched. Surfaces move over one at a time;
// crossdetect retires when the last one has moved. Nothing is cut over in this commit.
package estategraph

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// Kind classifies what a node IS — which determines how an attacker can use it.
type Kind string

const (
	KindPrincipal Kind = "principal" // an identity: IAM role, service account, human, warehouse role
	KindResource  Kind = "resource"  // compute, a bucket, a SaaS app, a device
	KindData      Kind = "data"      // something holding data: a table, a bucket, a dataset
	KindCode      Kind = "code"      // a repository, a package, a build pipeline
	KindSecret    Kind = "secret"    // a credential — the classic bridge between surfaces
	KindNetwork   Kind = "network"   // the internet pseudo-node, a VPC
)

// InternetID is the pseudo-node every externally-reachable path starts from. Deliberately the same
// literal cloudgraph uses, so a ported cloud subgraph keeps its entry point.
const InternetID = "internet"

// Sensitivity is the data-classification signal. Metadata only — never the data itself.
type Sensitivity string

const (
	SensUnknown Sensitivity = ""
	SensLow     Sensitivity = "low"
	SensHigh    Sensitivity = "high" // PII / PHI / cardholder / secrets / prod
)

// EdgeKind is a move an attacker can make.
type EdgeKind string

const (
	EdgeReaches  EdgeKind = "reaches"   // src can reach dst over the network
	EdgeGrants   EdgeKind = "grants"    // src (a principal) holds access to dst
	EdgeAssumes  EdgeKind = "assumes"   // src can become dst (assume-role, impersonate, privesc)
	EdgeRunsAs   EdgeKind = "runs_as"   // src (compute) executes with dst's identity
	EdgeLeakedIn EdgeKind = "leaked_in" // src (a secret) was found exposed in dst
	EdgeStores   EdgeKind = "stores"    // src holds the data in dst
	EdgeOwns     EdgeKind = "owns"      // src administers dst
)

// ErrNoEvidence is returned when an edge is added without anything backing it. This is the package's
// load-bearing refusal, not an input-validation nicety.
var ErrNoEvidence = errors.New("estategraph: refusing an edge with no evidence — an agent must never traverse a hop nobody proved")

// Node is one thing in the estate.
type Node struct {
	// ID is the canonical, surface-qualified identifier (see Canonical).
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Surface names the detector family that asserted this node (cloud, code, warehouse, identity,
	// saas, device, osint). Kept so a reader can tell WHERE a claim came from; a node asserted by two
	// surfaces carries both, which is exactly the cross-surface join we want to make visible.
	Surfaces []string `json:"surfaces,omitempty"`
	Name     string   `json:"name,omitempty"`
	// Sensitive is the data classification. See MergeSensitivity for why it only ever rises.
	Sensitive Sensitivity `json:"sensitive,omitempty"`
	// Privileged marks an admin-ish identity.
	Privileged bool `json:"privileged,omitempty"`
	// Public marks something reachable from outside.
	Public bool `json:"public,omitempty"`
	// Evidence is the finding ids asserting this node exists. A node may legitimately have none (an
	// inventory lists resources without any finding attached); an EDGE may not.
	Evidence []string          `json:"evidence,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	// ObservedAt is when a surface last asserted it.
	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// Edge is one move, and what proves it.
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
	// Evidence is REQUIRED — the finding ids (or observation refs) that prove this edge. AddEdge
	// refuses without it.
	Evidence []string `json:"evidence"`
	// Why is the one-sentence reason a human reads. Not a substitute for Evidence.
	Why        string    `json:"why,omitempty"`
	Surface    string    `json:"surface,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// Graph is a tenant's estate. Not safe for concurrent writes; build then read.
type Graph struct {
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`

	out map[string][]int // node id → indices into Edges
	in  map[string][]int
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{Nodes: map[string]*Node{}, Edges: nil, out: map[string][]int{}, in: map[string][]int{}}
}

// AddNode inserts or MERGES a node. Merging is additive: surfaces and evidence union, sensitivity only
// rises, and a true flag is never flipped back to false — because two surfaces disagreeing about
// whether something is public means one of them SAW it public, and the safe reading of a disagreement
// about exposure is the worse one.
func (g *Graph) AddNode(n Node) *Node {
	if n.ID == "" {
		return nil
	}
	cur, ok := g.Nodes[n.ID]
	if !ok {
		cp := n
		cp.Surfaces = dedupe(n.Surfaces)
		cp.Evidence = dedupe(n.Evidence)
		g.Nodes[n.ID] = &cp
		return &cp
	}
	cur.Surfaces = dedupe(append(cur.Surfaces, n.Surfaces...))
	cur.Evidence = dedupe(append(cur.Evidence, n.Evidence...))
	cur.Sensitive = MergeSensitivity(cur.Sensitive, n.Sensitive)
	cur.Privileged = cur.Privileged || n.Privileged
	cur.Public = cur.Public || n.Public
	if cur.Name == "" {
		cur.Name = n.Name
	}
	if cur.Kind == "" {
		cur.Kind = n.Kind
	}
	if n.ObservedAt.After(cur.ObservedAt) {
		cur.ObservedAt = n.ObservedAt
	}
	for k, v := range n.Attrs {
		if cur.Attrs == nil {
			cur.Attrs = map[string]string{}
		}
		if _, exists := cur.Attrs[k]; !exists {
			cur.Attrs[k] = v
		}
	}
	return cur
}

// AddEdge records a move. It REFUSES an edge with no evidence (ErrNoEvidence) — the invariant this
// package exists to hold. Endpoints are auto-created as bare nodes when absent, so a surface can assert
// an edge before the node's own detector has run.
func (g *Graph) AddEdge(e Edge) error {
	if e.From == "" || e.To == "" {
		return errors.New("estategraph: edge needs both endpoints")
	}
	if e.From == e.To {
		return errors.New("estategraph: refusing a self-edge — it is not a move")
	}
	if len(dedupe(e.Evidence)) == 0 {
		return ErrNoEvidence
	}
	e.Evidence = dedupe(e.Evidence)

	for _, id := range []string{e.From, e.To} {
		if _, ok := g.Nodes[id]; !ok {
			g.AddNode(Node{ID: id, Surfaces: nonEmpty(e.Surface)})
		}
	}
	// Merge into an existing identical move rather than duplicating it — the same edge asserted by two
	// surfaces is corroboration, and it must not double-count in ChokePoints.
	for i := range g.Edges {
		if g.Edges[i].From == e.From && g.Edges[i].To == e.To && g.Edges[i].Kind == e.Kind {
			g.Edges[i].Evidence = dedupe(append(g.Edges[i].Evidence, e.Evidence...))
			if g.Edges[i].Why == "" {
				g.Edges[i].Why = e.Why
			}
			if e.ObservedAt.After(g.Edges[i].ObservedAt) {
				g.Edges[i].ObservedAt = e.ObservedAt
			}
			return nil
		}
	}
	g.Edges = append(g.Edges, e)
	idx := len(g.Edges) - 1
	g.out[e.From] = append(g.out[e.From], idx)
	g.in[e.To] = append(g.in[e.To], idx)
	return nil
}

// Merge folds another surface's subgraph in. This is the strangler seam: each surface builds its own
// small graph and merges, so surfaces move over one at a time without a flag day.
//
// An edge that fails the evidence invariant in the source is DROPPED, not smuggled in — merging is not
// a way around AddEdge.
func (g *Graph) Merge(other *Graph) {
	if other == nil {
		return
	}
	for _, n := range other.Nodes {
		g.AddNode(*n)
	}
	for _, e := range other.Edges {
		_ = g.AddEdge(e)
	}
}

// Out returns the edges leaving a node.
func (g *Graph) Out(id string) []Edge {
	var out []Edge
	for _, i := range g.out[id] {
		out = append(out, g.Edges[i])
	}
	return out
}

// In returns the edges arriving at a node.
func (g *Graph) In(id string) []Edge {
	var out []Edge
	for _, i := range g.in[id] {
		out = append(out, g.Edges[i])
	}
	return out
}

// Neighbors returns the ids one hop out — the primitive an agent needs to pivot, which reading a
// pre-rendered chain summary cannot give it.
func (g *Graph) Neighbors(id string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range g.Out(id) {
		if !seen[e.To] {
			seen[e.To] = true
			out = append(out, e.To)
		}
	}
	sort.Strings(out)
	return out
}

// Path is a proven route through the estate.
type Path struct {
	Nodes []string `json:"nodes"`
	Edges []Edge   `json:"edges"`
}

// Crown reports whether a node is worth reaching.
func Crown(n *Node) bool {
	return n != nil && (n.Sensitive == SensHigh || n.Privileged)
}

// PathsFrom enumerates simple paths from a start node to any node satisfying want, up to maxDepth hops
// and maxPaths results.
//
// Bounded on purpose: path enumeration is exponential, and an agent that stalls is worse than one that
// reports the first N routes. Both caps are reported to the caller by truncation rather than silently
// applied — see Truncated.
func (g *Graph) PathsFrom(start string, want func(*Node) bool, maxDepth, maxPaths int) ([]Path, bool) {
	if maxDepth <= 0 {
		maxDepth = 6
	}
	if maxPaths <= 0 {
		maxPaths = 50
	}
	if _, ok := g.Nodes[start]; !ok {
		return nil, false
	}
	var out []Path
	truncated := false
	onPath := map[string]bool{start: true}
	var cur Path
	cur.Nodes = []string{start}

	var walk func(id string)
	walk = func(id string) {
		if len(out) >= maxPaths {
			truncated = true
			return
		}
		if len(cur.Edges) > 0 && want(g.Nodes[id]) {
			out = append(out, Path{Nodes: append([]string(nil), cur.Nodes...), Edges: append([]Edge(nil), cur.Edges...)})
			// Do not stop: a crown jewel can be a stepping stone to another.
		}
		if len(cur.Edges) >= maxDepth {
			truncated = true
			return
		}
		for _, e := range g.Out(id) {
			if onPath[e.To] {
				continue // simple paths only; a cycle is not a new route
			}
			onPath[e.To] = true
			cur.Nodes = append(cur.Nodes, e.To)
			cur.Edges = append(cur.Edges, e)
			walk(e.To)
			cur.Nodes = cur.Nodes[:len(cur.Nodes)-1]
			cur.Edges = cur.Edges[:len(cur.Edges)-1]
			delete(onPath, e.To)
		}
	}
	walk(start)
	return out, truncated
}

// ChokePoint is one node that many paths run through.
type ChokePoint struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Paths int    `json:"paths"`
	Why   string `json:"why"`
}

// ChokePoints ranks the nodes that the most paths traverse — real betweenness over enumerated routes,
// rather than counting occurrences in rendered chain text.
//
// Endpoints are excluded: the source is where every path starts and the crown is where it ends, so
// neither is a choke point. "Fix the thing being attacked" is not a finding.
func ChokePoints(paths []Path) []ChokePoint {
	count := map[string]int{}
	for _, p := range paths {
		if len(p.Nodes) < 3 {
			continue // no interior to be a choke point
		}
		seen := map[string]bool{}
		for _, id := range p.Nodes[1 : len(p.Nodes)-1] {
			if seen[id] {
				continue // once per path, or a path revisiting a node would outrank three distinct routes
			}
			seen[id] = true
			count[id]++
		}
	}
	var out []ChokePoint
	for id, c := range count {
		if c < 2 {
			continue // appearing in one path is not leverage, it IS the path
		}
		out = append(out, ChokePoint{ID: id, Paths: c,
			Why: "Cutting this severs " + plural(c, "attack path") + "."})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Paths != out[j].Paths {
			return out[i].Paths > out[j].Paths
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// MergeSensitivity takes the higher classification. Sensitivity only ever RISES on merge: if one
// surface says a table holds PII and another has no opinion, the answer is PII. Letting an
// unclassified assertion clear a positive one would silently downgrade a crown jewel — which is how a
// path stops looking like it matters.
func MergeSensitivity(a, b Sensitivity) Sensitivity {
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func rank(s Sensitivity) int {
	switch s {
	case SensHigh:
		return 2
	case SensLow:
		return 1
	}
	return 0
}

// Canonical normalises a raw identifier into a stable node id, so two surfaces naming the same
// real-world thing converge on one node. This is the whole cross-surface premise.
//
// EXACT, NEVER FUZZY. Every rule below is a deterministic rewrite of a known identifier FORMAT — case,
// scheme, a trailing slash, a provider's own prefix. Nothing here merges on resemblance or edit
// distance. A wrong merge fabricates a path that does not exist, and a fabricated path is worse than
// the two disconnected subgraphs we have today: it would send someone to sever a link that was never
// there while the real route stayed open.
//
// An unrecognised identifier keeps its own namespace rather than being forced into one — an unjoined
// node is honest, a wrongly-joined one is not.
func Canonical(surface, raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)

	switch {
	case strings.HasPrefix(low, "arn:"):
		// ARNs are globally unique and case-significant only in the resource tail; the account/service
		// prefix is not. Lowering the whole thing is safe for joining and keeps two spellings together.
		return "cloud:" + low
	case strings.HasSuffix(low, ".iam.gserviceaccount.com") && strings.Contains(low, "@"):
		// A GCP service account is the SAME principal whether a warehouse grant or the cloud inventory
		// named it. This single rule is what lets a Snowflake grantee join the cloud graph.
		return "principal:" + low
	case strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "http://"):
		u := strings.TrimSuffix(low, "/")
		u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		return "host:" + u
	case strings.Count(low, "@") == 1 && strings.Contains(low[strings.Index(low, "@"):], "."):
		return "principal:" + low // a human or a service identity, by email
	}
	if surface == "" {
		return "id:" + low
	}
	return surface + ":" + low
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func nonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return itoa(n) + " " + noun + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
