// Package cloudengine is the AI Cloud Security Engineer's reasoning core
// (ADR 0002, docs/design/ai-cloud-engineer.md). Assess runs the deterministic
// 6-phase investigation over a pinned snapshot + the prowler findings and
// produces the dual-view AIAssessment ("engineer says", alongside "tools say").
//
// This is the deterministic spine the design calls the "heavy lifting prepass":
// orientation, hypothesis enumeration (FindPaths), prioritization, validation
// (via a Validator), and finding construction with evidence + remediation. An
// LLM layer (the C3 agent) can sit on top for adaptive judgment, but the spine
// is complete, reproducible (snapshot_hash), and fully unit-testable on its own.
package cloudengine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Options bounds the investigation (the termination/efficiency governors).
type Options struct {
	MaxHypotheses int // worklist cap (top-K prioritized paths validated). Default 20.
	MaxDepth      int // path length cap. Default 8.
}

func (o Options) withDefaults() Options {
	if o.MaxHypotheses <= 0 {
		o.MaxHypotheses = 20
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 8
	}
	return o
}

// Validator climbs the validation ladder for a candidate path (ADR 0002). In
// production it routes live AWS analysis calls through cloudsafety.Guard; in
// tests/synthetic it is an oracle over the snapshot. Reachable=false means the
// path is config-possible but not live-reachable (a decoy) → downgraded.
type Validator interface {
	Validate(p cloudgraph.Path) (reachable bool, rung int, evidence []types.EvidenceItem)
}

// Assess runs the deterministic investigation and returns the dual-view block.
func Assess(snap *cloudgraph.Snapshot, prowler []types.Finding, v Validator, opts Options) *types.AIAssessment {
	opts = opts.withDefaults()
	rep := &types.AIAssessment{SnapshotHash: snap.Hash()}

	// 0. Prune over-approximated identity edges the effective IAM actually denies (an
	// assume-role edge blocked by the target's trust policy), so reachability isn't
	// over-stated — the held-out FP fix (cloudiam consulted before enumeration, §10).
	snap.PruneUnauthorized()

	// 1–2. Orient + hypothesize: from every entry point (internet + public
	// resources) find paths to a crown jewel (sensitive data OR privileged id).
	jewel := func(n *cloudgraph.Node) bool {
		return cloudgraph.SensitiveData(n) || cloudgraph.PrivilegedIdentity(n)
	}
	seen := map[string]bool{}
	var cands []cloudgraph.Path
	for _, entry := range entryPoints(snap) {
		for _, p := range snap.FindPaths(entry, jewel, cloudgraph.AllAttackEdges, opts.MaxDepth, opts.MaxHypotheses) {
			key := pathKey(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			cands = append(cands, p)
		}
	}
	// A public resource is also an entry point, so a chain can appear both
	// internet-rooted and rooted at the public resource (a suffix of it). Keep
	// the most-complete (internet-rooted) path; drop the dominated sub-paths.
	cands = dropDominated(cands)

	// 3. Prioritize: rank by impact heuristic, validate only the top-K.
	sort.SliceStable(cands, func(i, j int) bool {
		return score(snap, cands[i]) > score(snap, cands[j])
	})
	if len(cands) > opts.MaxHypotheses {
		cands = cands[:opts.MaxHypotheses]
	}

	// 4–5. Validate + build findings. Reachable → finding; unreachable → drop
	// (a config-possible-but-inert path; surfaced only via prowler downgrade).
	onRealPath := map[string]bool{}
	edgeUse := map[string]int{} // edge → #real paths it appears on (for cheapest-cut)
	id := 0
	for _, p := range cands {
		reachable, rung, ev := v.Validate(p)
		if !reachable {
			continue
		}
		id++
		for _, n := range p.Nodes {
			onRealPath[n] = true
		}
		for _, e := range p.Edges {
			edgeUse[edgeKey(e)]++
		}
		rep.Paths = append(rep.Paths, buildFinding(snap, fmt.Sprintf("acp-%03d", id), p, rung, ev))
	}

	// 6. Correlate prowler: a finding on a real path corroborates it; a prowler
	// finding touching no real path is a downgrade candidate (config-bad, inert).
	correlateProwler(rep, prowler, onRealPath)

	// Remediation: the cheapest edge to cut (appears on the most real paths).
	annotateRemediation(snap, rep, edgeUse)
	return rep
}

// entryPoints are where an attacker starts: the internet pseudo-node + every
// internet-exposed resource.
func entryPoints(snap *cloudgraph.Snapshot) []string {
	out := []string{cloudgraph.InternetID}
	for id, n := range snap.Nodes {
		if n.Public && id != cloudgraph.InternetID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// score ranks a candidate path by attacker value: target sensitivity/privilege,
// shorter chains, and fewer runtime conditions (more plausibly reachable).
func score(snap *cloudgraph.Snapshot, p cloudgraph.Path) float64 {
	if len(p.Nodes) == 0 {
		return 0
	}
	target := snap.Node(p.Nodes[len(p.Nodes)-1])
	s := 0.0
	if target != nil {
		switch target.Sensitive {
		case cloudgraph.SensHigh:
			s += 10
		case cloudgraph.SensLow:
			s += 3
		}
		if target.Privileged {
			s += 8
		}
	}
	s -= float64(len(p.Edges)) * 0.5 // prefer shorter chains
	if p.Conditional() {
		s -= 2 // conditions may block at runtime
	}
	return s
}

func buildFinding(snap *cloudgraph.Snapshot, id string, p cloudgraph.Path, rung int, ev []types.EvidenceItem) types.AttackPath {
	target := snap.Node(p.Nodes[len(p.Nodes)-1])
	ri := types.RealImpact{ConfigPossible: true, LiveReachable: true}
	if target != nil {
		ri.DataSensitivity = string(target.Sensitive)
		if target.Privileged {
			ri.Privilege = "privileged identity"
		}
	}
	ri.Score = impactScore(ri)

	ver := types.VerificationPatternMatch // rung 0–1: reasoned
	if rung >= 4 {
		ver = types.VerificationVerified
	} else if rung >= 3 {
		ver = types.VerificationCorroborated
	}

	return types.AttackPath{
		ID:           id,
		Narrative:    narrate(snap, p),
		Graph:        pathGraph(snap, p),
		RealImpact:   ri,
		Verification: ver,
		RungReached:  rung,
		Confidence:   confidence(rung, ri),
		Evidence:     ev,
		Affected:     affected(p),
		Compliance:   pathCompliance(p, target),
	}
}

func impactScore(ri types.RealImpact) float64 {
	if !ri.ConfigPossible || !ri.LiveReachable {
		return 0
	}
	if ri.DataSensitivity == string(cloudgraph.SensHigh) || ri.Privilege != "" {
		return 1.0
	}
	if ri.DataSensitivity == string(cloudgraph.SensLow) {
		return 0.5
	}
	return 0.3
}

func confidence(rung int, ri types.RealImpact) float64 {
	c := 0.5
	if rung >= 3 {
		c = 0.8
	}
	if rung >= 4 {
		c = 0.95
	}
	if ri.Score >= 1.0 {
		c += 0.04
	}
	if c > 0.99 {
		c = 0.99
	}
	return c
}

// narrate renders the chain in plain English (the non-security view).
func narrate(snap *cloudgraph.Snapshot, p cloudgraph.Path) string {
	var b strings.Builder
	verb := map[cloudgraph.EdgeKind]string{
		cloudgraph.EdgeNetworkReach: "reaches", cloudgraph.EdgeRunsAs: "runs as",
		cloudgraph.EdgeAssumeRole: "assumes", cloudgraph.EdgePassRole: "passes",
		cloudgraph.EdgeHasAccess: "reads", cloudgraph.EdgePrivesc: "escalates to",
	}
	b.WriteString(label(snap, p.Nodes[0]))
	for i, e := range p.Edges {
		v := verb[e.Kind]
		if v == "" {
			v = "→"
		}
		fmt.Fprintf(&b, " %s %s", v, label(snap, p.Nodes[i+1]))
	}
	return b.String()
}

func label(snap *cloudgraph.Snapshot, id string) string {
	if n := snap.Node(id); n != nil && n.Name != "" {
		return n.Name
	}
	return id
}

func pathGraph(snap *cloudgraph.Snapshot, p cloudgraph.Path) types.PathGraph {
	g := types.PathGraph{}
	for _, id := range p.Nodes {
		n := snap.Node(id)
		pn := types.PathNode{ID: id, Label: label(snap, id)}
		if n != nil {
			pn.Kind = string(n.Kind)
		}
		g.Nodes = append(g.Nodes, pn)
	}
	for _, e := range p.Edges {
		g.Edges = append(g.Edges, types.PathEdge{From: e.From, To: e.To, Kind: string(e.Kind)})
	}
	return g
}

func affected(p cloudgraph.Path) []string {
	out := append([]string(nil), p.Nodes...)
	sort.Strings(out)
	return out
}

func correlateProwler(rep *types.AIAssessment, prowler []types.Finding, onRealPath map[string]bool) {
	for _, f := range prowler {
		res := resourceOf(f)
		if res == "" {
			continue
		}
		if onRealPath[res] {
			attachCorroborates(rep, res, f.ID)
		} else {
			// config-bad but on no real path → the engineer's FP-reduction signal.
			rep.AuditLog = append(rep.AuditLog,
				fmt.Sprintf("downgraded prowler %s on %s: config-bad but not on any reachable path", f.ID, res))
			rep.Downgraded = appendUnique(rep.Downgraded, f.ID)
		}
	}
}

// resourceOf extracts the resource id a prowler finding is about (Endpoint =
// "<type> <name> @<region>" per the prowler parser; the name is the join key).
func resourceOf(f types.Finding) string {
	parts := strings.Fields(f.Endpoint)
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.TrimSpace(f.Endpoint)
}

func attachCorroborates(rep *types.AIAssessment, res, findingID string) {
	for i := range rep.Paths {
		for _, a := range rep.Paths[i].Affected {
			if a == res {
				rep.Paths[i].Corroborates = appendUnique(rep.Paths[i].Corroborates, findingID)
				return
			}
		}
	}
}

func annotateRemediation(snap *cloudgraph.Snapshot, rep *types.AIAssessment, edgeUse map[string]int) {
	for i := range rep.Paths {
		best, bestN := "", -1
		for _, e := range rep.Paths[i].Graph.Edges {
			k := e.From + "->" + e.To + ":" + e.Kind
			if edgeUse[k] > bestN {
				bestN, best = edgeUse[k], cutAdvice(e)
			}
		}
		if best != "" {
			rep.Paths[i].Remediation = best
		}
	}
}

func cutAdvice(e types.PathEdge) string {
	switch cloudgraph.EdgeKind(e.Kind) {
	case cloudgraph.EdgeAssumeRole:
		return fmt.Sprintf("scope %s's trust policy so %s can no longer assume it (cuts the chain)", e.To, e.From)
	case cloudgraph.EdgeHasAccess:
		return fmt.Sprintf("remove %s's access to %s", e.From, e.To)
	case cloudgraph.EdgeNetworkReach:
		return fmt.Sprintf("close the network path %s → %s", e.From, e.To)
	case cloudgraph.EdgePrivesc:
		return fmt.Sprintf("remove the privilege-escalation grant on %s", e.From)
	default:
		return fmt.Sprintf("break the %s edge %s → %s", e.Kind, e.From, e.To)
	}
}

// dropDominated removes any candidate whose node sequence is a contiguous
// suffix of a longer candidate's (the same attack seen from a later start).
func dropDominated(cands []cloudgraph.Path) []cloudgraph.Path {
	keep := make([]bool, len(cands))
	for i := range cands {
		keep[i] = true
	}
	for i := range cands {
		for j := range cands {
			if i == j || !keep[j] {
				continue
			}
			if len(cands[j].Nodes) > len(cands[i].Nodes) && isSuffix(cands[i].Nodes, cands[j].Nodes) {
				keep[i] = false
				break
			}
		}
	}
	out := cands[:0:0]
	for i, k := range keep {
		if k {
			out = append(out, cands[i])
		}
	}
	return out
}

func isSuffix(short, long []string) bool {
	if len(short) > len(long) {
		return false
	}
	off := len(long) - len(short)
	for i := range short {
		if short[i] != long[off+i] {
			return false
		}
	}
	return true
}

func pathKey(p cloudgraph.Path) string { return strings.Join(p.Nodes, ">") }
func edgeKey(e cloudgraph.Edge) string {
	return e.From + "->" + e.To + ":" + string(e.Kind)
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}
