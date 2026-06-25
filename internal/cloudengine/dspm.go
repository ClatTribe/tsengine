package cloudengine

import (
	"fmt"
	"sort"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// DSPM (data-security posture) — Phase 1 of the cloud-parity plan (ADR 0009). Wiz/Aikido flag
// a sensitive data store that is directly internet-exposed as a finding on its own ("public
// bucket with PII"). Our attack-path reasoning DIDN'T cover this: a path needs a multi-hop
// chain to a crown jewel, so a store that is its OWN entry point AND its own jewel (public ∧
// sensitive, with no onward edges) produced no finding. DSPMExposures fills exactly that gap.
//
// Grounded (§10): emits ONLY from the node's own classification metadata — Public (the
// resource's ACL/policy says internet-reachable) AND a sensitivity class — never inferred from
// the data itself (we never read bytes). Modeled as a one-hop internet→store attack path so it
// reuses every downstream renderer (severity, narrative, graph, compliance crosswalk).

// isDataStore reports whether a node type holds data worth a DSPM verdict. KindData always
// qualifies; otherwise we match the storage resource types (so a public *compute* node isn't a
// data-exposure — that's CSPM/attack-path territory).
func isDataStore(n *cloudgraph.Node) bool {
	if n == nil {
		return false
	}
	// KindData always qualifies; otherwise classify the type across AWS/GCP/Azure (Phase 4).
	return n.Kind == cloudgraph.KindData || cloudgraph.IsDataStoreType(n.Type)
}

// publicSensitive reports the DSPM trigger: an internet-exposed, sensitivity-classified data
// store. Both signals must come from the node's own config (grounded).
func publicSensitive(n *cloudgraph.Node) bool {
	return n != nil && n.Public && n.Sensitive != cloudgraph.SensNone && isDataStore(n)
}

// DSPMExposures returns a one-hop internet→store attack path for every public, sensitive data
// store NOT already covered by a discovered multi-hop path (`covered` = node ids already on a
// real path, so we never double-report). Deterministic + sorted for stable output.
func DSPMExposures(snap *cloudgraph.Snapshot, covered map[string]bool) []types.AttackPath {
	if snap == nil {
		return nil
	}
	ids := make([]string, 0, len(snap.Nodes))
	for id, n := range snap.Nodes {
		if publicSensitive(n) && !covered[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	out := make([]types.AttackPath, 0, len(ids))
	for i, id := range ids {
		n := snap.Node(id)
		// A synthetic one-hop path: the internet reaches the store directly (the node's
		// own public flag IS the network-reach edge). buildFinding then gives us the
		// narrative, path graph, RealImpact, and the public+sensitive compliance crosswalk
		// (pathCompliance) for free — zero new rendering code.
		p := cloudgraph.Path{
			Nodes: []string{cloudgraph.InternetID, id},
			Edges: []cloudgraph.Edge{{From: cloudgraph.InternetID, To: id, Kind: cloudgraph.EdgeNetworkReach}},
		}
		ap := buildFinding(snap, fmt.Sprintf("dspm-%03d", i+1), p, 1, []types.EvidenceItem{dspmEvidence(n)})
		// Make the DSPM nature explicit (buildFinding's generic narrative reads like a chain).
		ap.Narrative = fmt.Sprintf("%s (%s) is internet-exposed and classified %s-sensitivity: sensitive data is directly reachable from the public internet — no further compromise is required.",
			dspmName(n), n.Type, sensLabel(n.Sensitive))
		ap.Remediation = "Remove public access (enable block-public-access / restrict the resource policy to intended principals) and re-confirm the store is not internet-reachable."
		out = append(out, ap)
	}
	return out
}

func dspmEvidence(n *cloudgraph.Node) types.EvidenceItem {
	return types.EvidenceItem{
		Query:       fmt.Sprintf("inventory.node(%s)", n.ID),
		Observation: fmt.Sprintf("config: public=true, sensitivity=%q, type=%q, region=%q", n.Sensitive, n.Type, n.Region),
		AtRung:      0, // snapshot/config reasoning, not a live probe (honest)
	}
}

func dspmName(n *cloudgraph.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

func sensLabel(s cloudgraph.Sensitivity) string {
	if s == cloudgraph.SensNone {
		return "no"
	}
	return string(s)
}
