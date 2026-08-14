// Package estateingest moves surfaces across the strangler seam into the estate graph.
//
// estategraph is deliberately a LEAF — it knows nothing about clouds, warehouses or findings, so it
// cannot accumulate a dependency on every detector in the tree. This package is where the knowledge
// lives: one converter per surface, each importing its own source package and emitting a subgraph that
// Merge folds together.
//
// # What "evidence" means here
//
// estategraph.AddEdge refuses an edge that cites nothing, so every converter has to answer: what proves
// this? The answer is not always a finding id, and it should not be — a finding is a PROBLEM, while the
// graph is the ESTATE, and most of the estate is unremarkable. What is required is a CITABLE
// OBSERVATION, something a reader can go back to and re-check:
//
//   - cloud edges cite the pinned snapshot (cloudsnap:<Hash()>) — content-addressed, so the exact state
//     an edge was derived from is recoverable (§10's pinned-context rule)
//   - warehouse edges cite the ingest reference for the snapshot that carried the grant
//   - leaked-credential edges cite the finding that found the secret
//
// # The join is exact or it does not happen
//
// The cross-surface premise is that a warehouse grantee and a cloud service account are ONE node. That
// works when both surfaces name the same identifier, and Canonical converges them. Where an identifier
// is absent, the converters leave the node UNJOINED rather than inferring a link: a fabricated edge
// sends someone to sever a path that never existed while the real one stays open.
//
// The clearest case is a leaked AWS key. Code says "AKIA… is exposed"; that alone does not say WHICH
// principal it belongs to. We create the secret node and the exposure edge, and we connect it to a
// principal only when the cloud inventory itself says that principal holds that key id. No inventory
// data, no bridge — see TestLeakedKey_DoesNotInventTheCloudPrincipal.
package estateingest

import (
	"regexp"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/dataplatform"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Surface names, used as the node namespace for identifiers that do not canonicalise to a shared form.
const (
	SurfaceCloud     = "cloud"
	SurfaceWarehouse = "warehouse"
	SurfaceCode      = "code"
)

// AccessKeyIDAttr is the cloud-node attribute naming a principal's long-lived access key. It is the
// ONLY grounded way to connect a leaked key in code to the identity it unlocks: the inventory has to
// tell us whose key it is. Emitting it is the cloud ingest's job (the credential-gated half); absent
// it, the code→cloud bridge stays honestly open.
const AccessKeyIDAttr = "access_key_id"

// akiaRe matches an AWS access key id. Same shape as remediate's extractor (which is unexported);
// duplicated rather than exported across packages because it is three tokens and a shared regexp would
// couple remediation to ingest for no gain.
var akiaRe = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)

// FromCloud converts a pinned cloud inventory into estate-graph form.
//
// Every edge cites the snapshot hash, so an auditor can recover the exact state it came from. The
// snapshot is the observation; the graph is a view of it.
func FromCloud(snap *cloudgraph.Snapshot) *estategraph.Graph {
	g := estategraph.New()
	if snap == nil {
		return g
	}
	ref := "cloudsnap:" + snap.Hash()
	at := snap.CapturedAt

	for _, n := range snap.Nodes {
		if n == nil {
			continue
		}
		id := cloudNodeID(n.ID)
		g.AddNode(estategraph.Node{
			ID: id, Kind: cloudKind(n.Kind), Name: n.Name,
			Surfaces:   []string{SurfaceCloud},
			Sensitive:  cloudSensitivity(n.Sensitive),
			Privileged: n.Privileged, Public: n.Public,
			ObservedAt: at,
			Attrs:      n.Attrs,
		})

		// A principal whose access key the inventory records gets a secret node of its own. This is the
		// anchor a leaked key in code joins onto — and it only exists because the inventory said so.
		if key := strings.TrimSpace(n.Attrs[AccessKeyIDAttr]); key != "" {
			sid := secretID(key)
			g.AddNode(estategraph.Node{
				ID: sid, Kind: estategraph.KindSecret, Name: key,
				Surfaces: []string{SurfaceCloud}, ObservedAt: at,
			})
			_ = g.AddEdge(estategraph.Edge{
				From: sid, To: id, Kind: estategraph.EdgeAssumes,
				Evidence: []string{ref}, Surface: SurfaceCloud, ObservedAt: at,
				Why: "The inventory records this access key as belonging to " + nameOr(n.Name, id) + ".",
			})
		}
	}

	for _, e := range snap.Edges {
		kind, ok := cloudEdgeKind(e.Kind)
		if !ok {
			continue // an unmapped relationship is dropped, not guessed into the nearest kind
		}
		why := e.Detail
		if why == "" {
			why = "From the cloud inventory (" + string(e.Kind) + ")."
		}
		if e.Condition != "" {
			// Config-possible ≠ exploitable (ADR 0002). Carry the gate rather than presenting a
			// conditional edge as an unconditional one.
			why += " Gated at runtime by: " + e.Condition + "."
		}
		_ = g.AddEdge(estategraph.Edge{
			From: cloudNodeID(e.From), To: cloudNodeID(e.To), Kind: kind,
			Evidence: []string{ref}, Surface: SurfaceCloud, ObservedAt: at, Why: why,
		})
	}
	return g
}

// FromWarehouse converts a data-warehouse grant snapshot into estate-graph form.
//
// This is the surface that motivated the whole substrate: a grantee is a PRINCIPAL, and when it is a
// service account it is the SAME principal the cloud inventory knows. ref is the citable observation
// for the snapshot (an ingest id); it is required for the same reason AddEdge requires evidence.
func FromWarehouse(est dataplatform.Estate, ref string, now time.Time) *estategraph.Graph {
	g := estategraph.New()
	if strings.TrimSpace(ref) == "" {
		// No citable observation → no edges could be added anyway. Returning empty is honest; inventing
		// a reference so the edges "work" would defeat the invariant.
		return g
	}
	for _, o := range est.Objects {
		name := strings.TrimSpace(o.Name)
		if name == "" {
			continue
		}
		objID := estategraph.Canonical(SurfaceWarehouse, qualify(o.Platform, name))
		g.AddNode(estategraph.Node{
			ID: objID, Kind: estategraph.KindData, Name: name,
			Surfaces:   []string{SurfaceWarehouse},
			Sensitive:  warehouseSensitivity(o),
			ObservedAt: now,
			Attrs:      map[string]string{"platform": o.Platform, "object_type": o.Type},
		})

		for _, gr := range o.Grants {
			grantee := strings.TrimSpace(gr.Grantee)
			if grantee == "" {
				continue
			}
			// THE JOIN. A service-account grantee canonicalises into the shared principal namespace, so
			// it lands on the very node the cloud inventory created. A bare role name keeps the
			// warehouse namespace — unjoined and honest.
			pid := estategraph.Canonical(SurfaceWarehouse, grantee)
			g.AddNode(estategraph.Node{
				ID: pid, Kind: estategraph.KindPrincipal, Name: grantee,
				Surfaces: []string{SurfaceWarehouse}, ObservedAt: now,
				Public: isEveryone(grantee),
			})
			_ = g.AddEdge(estategraph.Edge{
				From: pid, To: objID, Kind: estategraph.EdgeGrants,
				Evidence: []string{ref}, Surface: SurfaceWarehouse, ObservedAt: now,
				Why: grantee + " holds " + strings.ToUpper(nameOr(gr.Privilege, "access")) + " on " + name + ".",
			})
		}
	}
	return g
}

// FromLeakedSecrets turns secret-scanner findings into secret nodes and their exposure.
//
// It creates the secret and the fact that it is exposed. It does NOT connect the secret to a cloud
// identity: a scanner finding says a key is public, never whose key it is. The bridge completes only if
// FromCloud independently produced the same secret node from the inventory's own record — an exact join
// on the key id, or nothing.
func FromLeakedSecrets(findings []types.Finding, now time.Time) *estategraph.Graph {
	g := estategraph.New()
	for _, f := range findings {
		key := awsKeyID(f)
		if key == "" {
			continue
		}
		sid := secretID(key)
		g.AddNode(estategraph.Node{
			ID: sid, Kind: estategraph.KindSecret, Name: key,
			Surfaces: []string{SurfaceCode}, Public: true, ObservedAt: now,
			Evidence: []string{f.ID},
		})
		where := estategraph.Canonical(SurfaceCode, nameOr(f.Endpoint, "unknown-location"))
		g.AddNode(estategraph.Node{
			ID: where, Kind: estategraph.KindCode, Name: f.Endpoint,
			Surfaces: []string{SurfaceCode}, ObservedAt: now, Evidence: []string{f.ID},
		})
		_ = g.AddEdge(estategraph.Edge{
			From: sid, To: where, Kind: estategraph.EdgeLeakedIn,
			Evidence: []string{f.ID}, Surface: SurfaceCode, ObservedAt: now,
			Why: "This access key was found exposed at " + f.Endpoint + ".",
		})
	}
	return g
}

// awsKeyID pulls a leaked access key id out of a finding's own text. Grounded: it matches the finding's
// evidence, never the rule name or a guess about what a scanner "probably" found.
func awsKeyID(f types.Finding) string {
	for _, s := range []string{f.Description, f.Title, f.Endpoint} {
		if m := akiaRe.FindString(s); m != "" {
			return m
		}
	}
	return ""
}

func secretID(key string) string {
	// Shared namespace, not per-surface: the whole point is that code and cloud converge on it.
	return "secret:" + strings.ToLower(strings.TrimSpace(key))
}

func cloudNodeID(raw string) string {
	if raw == cloudgraph.InternetID {
		return estategraph.InternetID // keep the well-known entry point shared across surfaces
	}
	return estategraph.Canonical(SurfaceCloud, raw)
}

func cloudKind(k cloudgraph.NodeKind) estategraph.Kind {
	switch k {
	case cloudgraph.KindPrincipal:
		return estategraph.KindPrincipal
	case cloudgraph.KindData:
		return estategraph.KindData
	case cloudgraph.KindNetwork:
		return estategraph.KindNetwork
	default:
		return estategraph.KindResource
	}
}

func cloudSensitivity(s cloudgraph.Sensitivity) estategraph.Sensitivity {
	switch s {
	case cloudgraph.SensHigh:
		return estategraph.SensHigh
	case cloudgraph.SensLow:
		return estategraph.SensLow
	}
	return estategraph.SensUnknown
}

// cloudEdgeKind maps a cloud relationship onto an estate move. Unmapped kinds return false and are
// DROPPED rather than coerced into the nearest neighbour — a mislabelled move reads as a capability the
// attacker does not have.
func cloudEdgeKind(k cloudgraph.EdgeKind) (estategraph.EdgeKind, bool) {
	switch k {
	case cloudgraph.EdgeAssumeRole, cloudgraph.EdgePassRole, cloudgraph.EdgePrivesc:
		return estategraph.EdgeAssumes, true
	case cloudgraph.EdgeHasAccess, cloudgraph.EdgeSecretAccess:
		return estategraph.EdgeGrants, true
	case cloudgraph.EdgeNetworkReach, cloudgraph.EdgeTriggers:
		return estategraph.EdgeReaches, true
	case cloudgraph.EdgeRunsAs:
		return estategraph.EdgeRunsAs, true
	case cloudgraph.EdgeCopyOf:
		return estategraph.EdgeStores, true
	}
	return "", false
}

// warehouseSensitivity carries the DECLARED classification through. dataplatform refuses to infer
// sensitivity from a table name, and that refusal must survive the trip into the graph — otherwise the
// graph would assert a crown jewel the detector deliberately declined to claim.
func warehouseSensitivity(o dataplatform.Object) estategraph.Sensitivity {
	if o.Sensitive {
		return estategraph.SensHigh
	}
	return estategraph.SensUnknown
}

// isEveryone recognises the built-in everyone-grantees, so a table granted to PUBLIC is marked exposed
// on the node itself rather than only inside a finding's prose.
func isEveryone(grantee string) bool {
	switch strings.ToLower(strings.TrimSpace(grantee)) {
	case "public", "allusers", "allauthenticatedusers":
		return true
	}
	return false
}

func qualify(platform, name string) string {
	if p := strings.TrimSpace(platform); p != "" {
		return p + ":" + name
	}
	return name
}

func nameOr(s, dflt string) string {
	if strings.TrimSpace(s) == "" {
		return dflt
	}
	return s
}
