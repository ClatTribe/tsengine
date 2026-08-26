package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/l2"
)

func adapterFixture(t *testing.T) *estateGraphAdapter {
	t.Helper()
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: estategraph.Canonical("web", "https://x/"), Kind: "endpoint", Surfaces: []string{"web"}, Public: true})
	g.AddNode(estategraph.Node{ID: estategraph.Canonical("code", "repo/app.py"), Kind: "code", Surfaces: []string{"code"}})
	g.AddNode(estategraph.Node{ID: estategraph.Canonical("cloud", "bucket/pii"), Kind: "data", Name: "PII bucket", Sensitive: estategraph.SensHigh, Surfaces: []string{"cloud"}})
	if err := g.AddEdge(estategraph.Edge{
		From: estategraph.Canonical("web", "https://x/"),
		To:   estategraph.Canonical("code", "repo/app.py"),
		Kind: estategraph.EdgeReaches, Evidence: []string{"f-1"}, Why: "the app serves this endpoint",
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(estategraph.Edge{
		From: estategraph.Canonical("code", "repo/app.py"),
		To:   estategraph.Canonical("cloud", "bucket/pii"),
		Kind: estategraph.EdgeStores, Evidence: []string{"f-2"}, Why: "app stores into the PII bucket",
	}); err != nil {
		t.Fatal(err)
	}
	return newEstateGraphAdapter(g)
}

// D6 wiring completion: traverse_estate's four ops answer from the composed graph,
// every hop carrying its evidence refs — the Lead cites the graph, not vibes.
func TestEstateAdapter_NeighborsCarryEvidence(t *testing.T) {
	a := adapterFixture(t)
	hops, err := a.Neighbors(context.Background(), estategraph.Canonical("web", "https://x/"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 1 || hops[0].Kind != string(estategraph.EdgeReaches) || len(hops[0].Evidence) == 0 {
		t.Fatalf("neighbors must carry kind + evidence, got %+v", hops)
	}
}

func TestEstateAdapter_PathsFromFindsCrownAndReportsTruncation(t *testing.T) {
	a := adapterFixture(t)
	paths, truncated, err := a.PathsFrom(context.Background(), estategraph.Canonical("web", "https://x/"))
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	found := false
	for _, p := range paths {
		for _, n := range p.Nodes {
			if strings.HasSuffix(n, "bucket/pii") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("crown path missing; paths=%+v", paths)
	}
}

func TestEstateAdapter_ChokePointsExcludeEndpoints(t *testing.T) {
	a := adapterFixture(t)
	cps, err := a.ChokePoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range cps {
		if cp.ID == estategraph.Canonical("web", "https://x/") {
			t.Errorf("the entry point is not a choke point: %+v", cp)
		}
	}
}

var _ l2.EstateGraph = (*estateGraphAdapter)(nil)
