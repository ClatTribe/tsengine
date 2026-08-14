package estateingest

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/dataplatform"
	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var now = time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

const gcpSA = "etl@acme.iam.gserviceaccount.com"

// warehouse returns a snapshot where a GCP service account can read a declared-PII table.
func warehouse() dataplatform.Estate {
	return dataplatform.Estate{Objects: []dataplatform.Object{{
		Platform: "snowflake", Name: "analytics.public.customers", Type: "table", Sensitive: true,
		Grants: []dataplatform.Grant{{Grantee: gcpSA, Privilege: "SELECT"}},
	}}}
}

// cloud returns an inventory where the internet reaches a VM that runs as that same service account.
func cloud() *cloudgraph.Snapshot {
	s := cloudgraph.New("acct-1", "gcp")
	s.Nodes[cloudgraph.InternetID] = &cloudgraph.Node{ID: cloudgraph.InternetID, Kind: cloudgraph.KindNetwork}
	s.Nodes["vm-1"] = &cloudgraph.Node{ID: "vm-1", Kind: cloudgraph.KindResource, Name: "etl-runner", Public: true}
	s.Nodes[gcpSA] = &cloudgraph.Node{ID: gcpSA, Kind: cloudgraph.KindPrincipal, Name: "etl"}
	s.Edges = append(s.Edges,
		cloudgraph.Edge{From: cloudgraph.InternetID, To: "vm-1", Kind: cloudgraph.EdgeNetworkReach},
		cloudgraph.Edge{From: "vm-1", To: gcpSA, Kind: cloudgraph.EdgeRunsAs},
	)
	return s
}

// ══ THE ONE THAT MATTERS ═════════════════════════════════════════════════════════════════════════
//
// Three surfaces, one path: the internet reaches a VM, the VM runs as a service account, and that
// service account — named by the WAREHOUSE, not the cloud — can read a PII table. Nothing in the
// product could express this before; crossdetect would have rendered it to prose at best.
func TestCloudAndWarehouseJoinIntoOnePath(t *testing.T) {
	g := estategraph.New()
	g.Merge(FromCloud(cloud()))
	g.Merge(FromWarehouse(warehouse(), "wh-ingest-1", now))

	// The service account must be ONE node carrying both surfaces — not two lookalikes.
	sa := estategraph.Canonical(SurfaceCloud, gcpSA)
	n := g.Nodes[sa]
	if n == nil {
		t.Fatalf("no node for the service account; ids present: %v", ids(g))
	}
	if len(n.Surfaces) != 2 {
		t.Errorf("surfaces = %v, want both cloud and warehouse on ONE node", n.Surfaces)
	}

	paths, _ := g.PathsFrom(estategraph.InternetID, estategraph.Crown, 6, 20)
	if len(paths) == 0 {
		t.Fatal("no path from the internet to the PII table — the cross-surface join failed")
	}
	var reached bool
	for _, p := range paths {
		if strings.Contains(p.Nodes[len(p.Nodes)-1], "customers") {
			reached = true
			// Every hop must carry its proof; this is what the agent cites when it reports the path.
			for _, e := range p.Edges {
				if len(e.Evidence) == 0 {
					t.Errorf("hop %s→%s carries no evidence", e.From, e.To)
				}
			}
		}
	}
	if !reached {
		t.Errorf("no path reached the PII table; got %d paths ending elsewhere", len(paths))
	}
}

// ══ THE REFUSAL THAT KEEPS IT HONEST ═════════════════════════════════════════════════════════════
//
// A secret scanner says a key is exposed. It does NOT say whose key it is. Bridging code→cloud on that
// alone would fabricate the product's headline attack path — the most tempting invention in the whole
// system, and the one that would most damage trust when someone checked it.
func TestLeakedKey_DoesNotInventTheCloudPrincipal(t *testing.T) {
	leak := []types.Finding{{
		ID: "f-gitleaks", Tool: "gitleaks", RuleID: "aws-access-key",
		Endpoint: "github.com/acme/api/config.tf:12",
		// No inventory anywhere says this key belongs to the role below.
		Description: "AWS access key AKIAIOSFODNN7EXAMPLE committed to the repository",
	}}
	g := estategraph.New()
	g.Merge(FromLeakedSecrets(leak, now))

	inv := cloudgraph.New("acct-1", "aws")
	inv.Nodes["arn:aws:iam::1:role/Admin"] = &cloudgraph.Node{
		ID: "arn:aws:iam::1:role/Admin", Kind: cloudgraph.KindPrincipal, Privileged: true,
	}
	g.Merge(FromCloud(inv))

	secret := "secret:akiaiosfodnn7example"
	if g.Nodes[secret] == nil {
		t.Fatal("the leaked key produced no secret node")
	}
	for _, e := range g.Out(secret) {
		if strings.Contains(e.To, "role/admin") {
			t.Error("INVENTED the code→cloud bridge: nothing said this key belongs to that role")
		}
	}
}

// And the converse — when the inventory DOES record the key, the bridge completes. Without this, the
// refusal above would be satisfied by a converter that simply never bridges anything.
func TestLeakedKey_BridgesWhenTheInventoryNamesTheKey(t *testing.T) {
	leak := []types.Finding{{
		ID: "f-gitleaks", Tool: "gitleaks", Endpoint: "github.com/acme/api/config.tf:12",
		Description: "AWS access key AKIAIOSFODNN7EXAMPLE committed to the repository",
	}}
	inv := cloudgraph.New("acct-1", "aws")
	inv.Nodes["arn:aws:iam::1:role/Admin"] = &cloudgraph.Node{
		ID: "arn:aws:iam::1:role/Admin", Kind: cloudgraph.KindPrincipal, Name: "Admin", Privileged: true,
		Attrs: map[string]string{AccessKeyIDAttr: "AKIAIOSFODNN7EXAMPLE"},
	}
	g := estategraph.New()
	g.Merge(FromLeakedSecrets(leak, now))
	g.Merge(FromCloud(inv))

	paths, _ := g.PathsFrom("secret:akiaiosfodnn7example", estategraph.Crown, 4, 10)
	if len(paths) == 0 {
		t.Fatal("the inventory named the key's owner, yet no path reaches the privileged role")
	}
	for _, e := range paths[0].Edges {
		if len(e.Evidence) == 0 {
			t.Error("the bridge edge cites nothing")
		}
	}
}

// ══ CARRYING THE SOURCE PACKAGES' REFUSALS THROUGH ═══════════════════════════════════════════════

// dataplatform deliberately refuses to infer sensitivity from a table name. If the graph re-asserted it,
// the refusal would be pointless: the graph would claim a crown jewel the detector declined to claim.
func TestWarehouse_UndeclaredSensitivityStaysUnknown(t *testing.T) {
	est := dataplatform.Estate{Objects: []dataplatform.Object{{
		Platform: "snowflake", Name: "prod.public.customers_pii_ssn", Type: "table", // Sensitive NOT set
		Grants: []dataplatform.Grant{{Grantee: "analyst_role", Privilege: "SELECT"}},
	}}}
	g := FromWarehouse(est, "wh-1", now)
	id := estategraph.Canonical(SurfaceWarehouse, "snowflake:prod.public.customers_pii_ssn")
	if n := g.Nodes[id]; n == nil || n.Sensitive == estategraph.SensHigh {
		t.Error("the graph asserted sensitivity from a table NAME, which the detector refused to do")
	}
}

// No citable observation → no edges. Inventing a reference so the edges "work" would defeat the
// invariant the substrate exists to hold.
func TestWarehouse_WithoutAReferenceAddsNoEdges(t *testing.T) {
	if g := FromWarehouse(warehouse(), "  ", now); len(g.Edges) != 0 {
		t.Errorf("added %d edges with no observation to cite", len(g.Edges))
	}
}

func TestCloud_EveryEdgeCitesThePinnedSnapshot(t *testing.T) {
	snap := cloud()
	g := FromCloud(snap)
	if len(g.Edges) == 0 {
		t.Fatal("no edges converted")
	}
	want := "cloudsnap:" + snap.Hash()
	for _, e := range g.Edges {
		if len(e.Evidence) != 1 || e.Evidence[0] != want {
			t.Errorf("edge %s→%s cites %v, want the pinned snapshot %q", e.From, e.To, e.Evidence, want)
		}
	}
}

// An unmapped relationship is dropped, not coerced into the nearest kind — a mislabelled move reads as
// a capability the attacker does not have.
func TestCloud_UnmappedEdgeKindIsDroppedNotCoerced(t *testing.T) {
	s := cloudgraph.New("a", "aws")
	s.Nodes["x"] = &cloudgraph.Node{ID: "x"}
	s.Nodes["y"] = &cloudgraph.Node{ID: "y"}
	s.Edges = append(s.Edges, cloudgraph.Edge{From: "x", To: "y", Kind: cloudgraph.EdgeKind("teleports")})
	if g := FromCloud(s); len(g.Edges) != 0 {
		t.Errorf("an unknown relationship became %v", g.Edges)
	}
}

// A conditional edge is config-possible, not proven exploitable (ADR 0002). The condition has to travel
// with it, or a reader takes a gated move for an open one.
func TestCloud_ConditionalEdgeKeepsItsGate(t *testing.T) {
	s := cloudgraph.New("a", "aws")
	s.Nodes["p"] = &cloudgraph.Node{ID: "p", Kind: cloudgraph.KindPrincipal}
	s.Nodes["q"] = &cloudgraph.Node{ID: "q", Kind: cloudgraph.KindPrincipal}
	s.Edges = append(s.Edges, cloudgraph.Edge{
		From: "p", To: "q", Kind: cloudgraph.EdgeAssumeRole, Condition: "aws:MultiFactorAuthPresent",
	})
	g := FromCloud(s)
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %d", len(g.Edges))
	}
	if !strings.Contains(g.Edges[0].Why, "MultiFactorAuthPresent") {
		t.Errorf("the runtime condition was dropped: %q", g.Edges[0].Why)
	}
}

// A grant to PUBLIC marks the node exposed, so exposure is visible on the graph itself rather than only
// inside a finding's prose — that is the difference between a graph and a list.
func TestWarehouse_PublicGranteeMarksTheNodeExposed(t *testing.T) {
	est := dataplatform.Estate{Objects: []dataplatform.Object{{
		Platform: "bigquery", Name: "proj.ds.t", Type: "table",
		Grants: []dataplatform.Grant{{Grantee: "allUsers", Privilege: "SELECT"}},
	}}}
	g := FromWarehouse(est, "wh-1", now)
	id := estategraph.Canonical(SurfaceWarehouse, "allusers")
	if n := g.Nodes[id]; n == nil || !n.Public {
		t.Errorf("the everyone-grantee was not marked public (node=%+v)", n)
	}
}

func TestConverters_HandleEmptyInput(t *testing.T) {
	if g := FromCloud(nil); g == nil || len(g.Nodes) != 0 {
		t.Error("nil snapshot did not yield an empty graph")
	}
	if g := FromWarehouse(dataplatform.Estate{}, "ref", now); len(g.Nodes) != 0 {
		t.Error("empty estate produced nodes")
	}
	if g := FromLeakedSecrets(nil, now); len(g.Nodes) != 0 {
		t.Error("no findings produced nodes")
	}
	// A finding with no key in it must not become a secret node.
	noKey := []types.Finding{{ID: "f", Description: "some other problem entirely"}}
	if g := FromLeakedSecrets(noKey, now); len(g.Nodes) != 0 {
		t.Error("a finding with no access key became a secret node")
	}
}

func ids(g *estategraph.Graph) []string {
	out := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		out = append(out, id)
	}
	return out
}
