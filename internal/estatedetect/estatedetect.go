// Package estatedetect turns the cross-surface estate graph into FINDINGS — detections that
// exist only because two surfaces were joined, and which no single-surface tool can produce.
//
// WHY THIS IS DETECTION AND NOT REPORTING. gitleaks can tell you a key is committed. prowler
// can tell you a role is over-privileged. Neither can tell you THIS committed key IS that role,
// and that the role reaches the customer-PII bucket — because neither can see the other's
// surface. That sentence is a new fact about the estate, and it is only derivable from the join.
// So the graph is not a nicer way to draw what we already knew; it is a detector.
//
// SCOPE DISCIPLINE — we only report what the join adds. A path that lives entirely inside one
// surface is already covered by that surface's own detector (cloudgraph enumerates cloud-only
// attack paths and reports them well). Emitting those here would duplicate a finding the customer
// already has, under a second name, which is how a "correlation layer" turns into noise. Every
// detection below therefore requires the evidence to span at least two surfaces.
//
// GROUNDING (§10). Every finding cites the EDGE evidence that proves each hop, and estategraph
// refuses to hold an edge with no evidence at all (ErrNoEvidence). So a path here cannot exist
// unless something really asserted every hop of it. No path, no finding — an estate with nothing
// joined yields nothing, which is the correct answer rather than a hedge.
package estatedetect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Options bound the enumeration. Path finding is exponential; an analysis that stalls is worse
// than one that reports the first N routes and says so.
type Options struct {
	MaxDepth int       // hops from the entry point (default 6)
	MaxPaths int       // routes enumerated per entry point (default 50)
	Now      time.Time // finding timestamp; zero → time.Now
}

func (o Options) norm() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 6
	}
	if o.MaxPaths <= 0 {
		o.MaxPaths = 50
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	return o
}

// Detect runs every cross-surface detection over the estate graph. A graph with nothing joined
// returns nil — the honest answer for an estate we have only seen one surface of.
func Detect(g *estategraph.Graph, opts Options) []types.Finding {
	if g == nil || len(g.Nodes) == 0 {
		return nil
	}
	o := opts.norm()
	n := 0
	id := func() string { n++; return fmt.Sprintf("estate-%03d", n) }

	var out []types.Finding
	out = append(out, detectSecretBridges(g, o, id)...)
	out = append(out, detectInternetToCrown(g, o, id)...)
	out = append(out, detectExposedIdentity(g, o, id)...)
	return out
}

// detectSecretBridges finds the canonical cross-surface exploit: a credential exposed on one
// surface that is a LIVE identity on another. The secret node carries both surfaces because code
// and cloud converge on the same shared id — that convergence IS the detection.
//
// A secret seen on only one surface is not reported here: a leaked key nobody can tie to a live
// principal is the code scanner's finding, already delivered, and repeating it adds nothing.
func detectSecretBridges(g *estategraph.Graph, o Options, id func() string) []types.Finding {
	var out []types.Finding
	for _, node := range sortedNodes(g) {
		if node.Kind != estategraph.KindSecret || len(node.Surfaces) < 2 {
			continue
		}
		// What does holding this credential actually get you? Only crowns count — a key to
		// nothing valuable is not an incident.
		paths, truncated := g.PathsFrom(node.ID, estategraph.Crown, o.MaxDepth, o.MaxPaths)
		if len(paths) == 0 {
			continue
		}
		reach, ev := summarize(g, paths)
		// The claim has TWO halves — "exposed" and "live" — so the evidence must cover both. The
		// paths above only prove the LIVE half (what the credential reaches). The EXPOSED half is
		// proven by the node's own evidence and its leaked_in edges, and without them this finding
		// would assert an exposure it never cited (§10).
		ev = dedupe(append(ev, exposureEvidence(g, node.ID)...))
		desc := fmt.Sprintf(
			"The credential %s is exposed on one surface (%s) and is a live identity on another. "+
				"Holding it reaches %s. Neither the code scanner nor the cloud scanner can see this on "+
				"its own — the code scanner does not know the key is live, and the cloud scanner does not "+
				"know it is published. Revoke the credential in the cloud first, then scrub it from the "+
				"code: scrubbing first leaves a working key in the attacker's hands.",
			nameOr(node.Name, node.ID), strings.Join(node.Surfaces, " + "), reach)
		if truncated {
			desc += " (Route enumeration hit its cap; more paths may exist.)"
		}
		out = append(out, finding(id(), "estate::leaked-credential-is-live", types.SeverityCritical,
			"Exposed credential is a live identity: "+nameOr(node.Name, node.ID),
			node.ID, desc, o.Now, ev))
	}
	return out
}

// detectInternetToCrown reports a route from the public internet to a crown jewel that CROSSES
// surfaces. The cross-surface requirement is what keeps this out of cloudgraph's territory: a
// cloud-only internet→admin path is cloudgraph's finding and is already reported there.
func detectInternetToCrown(g *estategraph.Graph, o Options, id func() string) []types.Finding {
	if _, ok := g.Nodes[estategraph.InternetID]; !ok {
		return nil
	}
	paths, truncated := g.PathsFrom(estategraph.InternetID, estategraph.Crown, o.MaxDepth, o.MaxPaths)
	var cross []estategraph.Path
	for _, p := range paths {
		if surfaceSpan(g, p) >= 2 {
			cross = append(cross, p)
		}
	}
	if len(cross) == 0 {
		return nil
	}
	var out []types.Finding
	// One finding per crown reached — the customer thinks in terms of "what can be taken", not
	// in terms of route count.
	byCrown := map[string][]estategraph.Path{}
	for _, p := range cross {
		byCrown[p.Nodes[len(p.Nodes)-1]] = append(byCrown[p.Nodes[len(p.Nodes)-1]], p)
	}
	for _, crown := range sortedKeys(byCrown) {
		ps := byCrown[crown]
		_, ev := summarize(g, ps)
		route := renderPath(g, ps[0])
		desc := fmt.Sprintf(
			"An attacker starting from the public internet can reach %s by crossing surfaces: %s. "+
				"This route is invisible to any single scanner because each hop belongs to a different "+
				"tool's view of your estate.",
			nameOr(g.Nodes[crown].Name, crown), route)
		if len(ps) > 1 {
			desc += fmt.Sprintf(" %d distinct routes reach it.", len(ps))
		}
		if truncated {
			desc += " (Route enumeration hit its cap; more paths may exist.)"
		}
		out = append(out, finding(id(), "estate::cross-surface-path-to-crown", types.SeverityCritical,
			"Internet reaches "+nameOr(g.Nodes[crown].Name, crown)+" across surfaces",
			crown, desc, o.Now, ev))
	}

	// The choke point is the actionable half: one node many routes share, so cutting it kills
	// them all. Only worth saying when it actually serves more than one route.
	if cps := estategraph.ChokePoints(cross); len(cps) > 0 && cps[0].Paths > 1 {
		cp := cps[0]
		out = append(out, finding(id(), "estate::choke-point", types.SeverityHigh,
			"One change cuts "+fmt.Sprint(cp.Paths)+" attack routes: "+nameOr(cp.Name, cp.ID),
			cp.ID,
			fmt.Sprintf("%s sits on %d of the routes from the internet to something valuable. %s "+
				"Fixing this one node closes more of the estate than fixing any single finding on those routes.",
				nameOr(cp.Name, cp.ID), cp.Paths, cp.Why),
			o.Now, evidenceOfNode(g, cp.ID)))
	}
	return out
}

// --- helpers ---

// surfaceSpan counts the distinct surfaces a path's EDGES were asserted by. Edges, not nodes: a
// node can carry several surfaces simply because two inventories both listed it, whereas an edge's
// surface is the tool that actually proved that hop — which is what "crosses surfaces" means.
func surfaceSpan(g *estategraph.Graph, p estategraph.Path) int {
	seen := map[string]bool{}
	for _, e := range p.Edges {
		if e.Surface != "" {
			seen[e.Surface] = true
		}
	}
	return len(seen)
}

// summarize renders what the paths reach and collects every piece of edge evidence behind them.
func summarize(g *estategraph.Graph, paths []estategraph.Path) (string, []string) {
	crowns := map[string]bool{}
	var ev []string
	for _, p := range paths {
		if len(p.Nodes) > 0 {
			last := p.Nodes[len(p.Nodes)-1]
			crowns[nameOr(g.Nodes[last].Name, last)] = true
		}
		for _, e := range p.Edges {
			ev = append(ev, e.Evidence...)
		}
	}
	return strings.Join(sortedSet(crowns), ", "), dedupe(ev)
}

// renderPath writes the route the way a person reads it: node → node → node, with each hop's
// reason attached when the ingest supplied one.
func renderPath(g *estategraph.Graph, p estategraph.Path) string {
	var b strings.Builder
	for i, nid := range p.Nodes {
		if i > 0 {
			b.WriteString(" → ")
		}
		b.WriteString(nameOr(g.Nodes[nid].Name, nid))
	}
	return b.String()
}

func evidenceOfNode(g *estategraph.Graph, id string) []string {
	if n, ok := g.Nodes[id]; ok {
		return dedupe(n.Evidence)
	}
	return nil
}

func sortedNodes(g *estategraph.Graph) []*estategraph.Node {
	out := make([]*estategraph.Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string { return sortedKeys(m) }

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func nameOr(name, alt string) string {
	if strings.TrimSpace(name) == "" {
		return alt
	}
	return name
}

func finding(fid, rule string, sev types.Severity, title, endpoint, desc string, now time.Time, ev []string) types.Finding {
	return types.Finding{
		ID: fid, RuleID: rule, Tool: "estate-graph", Severity: sev,
		Title: title, Endpoint: endpoint, Description: desc, DiscoveredAt: now,
		// The cross-surface joins map onto the same controls the single-surface findings do —
		// access control and boundary protection — because that is what the chain violates.
		Compliance: &types.Compliance{
			SOC2: []string{"CC6.1", "CC6.6"}, CISv8: []string{"3.3", "6.8"},
			NISTCSF: []string{"PR.AC-4"}, NIST80053: []string{"AC-3", "AC-6", "SC-7"},
			GDPR: []string{"Art. 32"}, ISO27001: []string{"A.5.15"},
		},
		DerivedFrom: ev,
	}
}

// exposureEvidence collects what proves a secret is EXPOSED: the node's own evidence plus every
// leaked_in edge out of it. Separate from the reachability evidence because they prove different
// halves of the same sentence.
func exposureEvidence(g *estategraph.Graph, id string) []string {
	var ev []string
	if n, ok := g.Nodes[id]; ok {
		ev = append(ev, n.Evidence...)
	}
	for _, e := range g.Out(id) {
		if e.Kind == estategraph.EdgeLeakedIn {
			ev = append(ev, e.Evidence...)
		}
	}
	return ev
}
