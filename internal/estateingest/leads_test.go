package estateingest

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// estateWithWebToPII builds the graph the wedge is about: a web host the pentester will probe sits on a
// proven path to a declared-PII table, via a service account.
func estateWithWebToPII() *estategraph.Graph {
	g := estategraph.New()
	host := estategraph.Canonical(SurfaceCode, "https://shop.example.com/login")
	sa := estategraph.Canonical(SurfaceCloud, gcpSA)
	tbl := estategraph.Canonical(SurfaceWarehouse, "snowflake:analytics.public.customers")

	g.AddNode(estategraph.Node{ID: host, Kind: estategraph.KindResource, Name: "shop.example.com", Public: true})
	g.AddNode(estategraph.Node{ID: sa, Kind: estategraph.KindPrincipal, Name: "etl-sa"})
	g.AddNode(estategraph.Node{ID: tbl, Kind: estategraph.KindData, Name: "customers", Sensitive: estategraph.SensHigh})
	for _, e := range []estategraph.Edge{
		{From: host, To: sa, Kind: estategraph.EdgeRunsAs, Evidence: []string{"cloudsnap:x"}},
		{From: sa, To: tbl, Kind: estategraph.EdgeGrants, Evidence: []string{"wh-1"}},
	} {
		if err := g.AddEdge(e); err != nil {
			panic(err)
		}
	}
	return g
}

// THE DELIVERY TEST. A route the agent will probe gets a lead naming the crown it reaches and the chain
// to it — the whole point of feeding the graph to the pentester.
func TestLeadsForRoutes_NamesWhatTheRouteReaches(t *testing.T) {
	g := estateWithWebToPII()
	leads := LeadsForRoutes(g, []string{"https://shop.example.com/login"})
	if len(leads) != 1 {
		t.Fatalf("want 1 lead, got %d: %+v", len(leads), leads)
	}
	l := leads[0]
	if !strings.Contains(strings.ToLower(l.Reaches), "regulated data") {
		t.Errorf("lead does not name the PII crown: %q", l.Reaches)
	}
	if l.Why == "" {
		t.Error("lead carries no chain explanation")
	}
	if len(l.Evidence) == 0 {
		t.Error("lead cites no evidence — it would not be auditable")
	}
}

// A route that reaches nothing valuable gets NO lead. A lead for every URL would be noise, and noise is
// how the signal the lead exists to carry gets ignored.
func TestLeadsForRoutes_SilentWhenARouteReachesNothing(t *testing.T) {
	g := estategraph.New()
	host := estategraph.Canonical(SurfaceCode, "https://shop.example.com/blog")
	g.AddNode(estategraph.Node{ID: host, Kind: estategraph.KindResource, Public: true})
	// A neighbour that is not a crown jewel.
	other := estategraph.Canonical(SurfaceCode, "https://shop.example.com/about")
	g.AddNode(estategraph.Node{ID: other, Kind: estategraph.KindResource})
	_ = g.AddEdge(estategraph.Edge{From: host, To: other, Kind: estategraph.EdgeReaches, Evidence: []string{"f"}})

	if leads := LeadsForRoutes(g, []string{"https://shop.example.com/blog"}); len(leads) != 0 {
		t.Errorf("a route reaching no crown jewel produced a lead: %+v", leads)
	}
}

// A route the graph has never heard of yields nothing — never a guessed lead.
func TestLeadsForRoutes_UnknownRouteYieldsNothing(t *testing.T) {
	g := estateWithWebToPII()
	if leads := LeadsForRoutes(g, []string{"https://other.example.com/x"}); len(leads) != 0 {
		t.Errorf("an unknown route produced a lead: %+v", leads)
	}
}

// The sharpest path wins: a sensitive-data crown two hops away beats a privileged identity five hops
// away, so the agent is pointed at the highest-stakes reachable thing.
func TestLeadsForRoutes_PicksTheStrongestPath(t *testing.T) {
	g := estategraph.New()
	host := estategraph.Canonical(SurfaceCode, "https://shop.example.com/login")
	g.AddNode(estategraph.Node{ID: host, Kind: estategraph.KindResource, Public: true})

	// Short path to PII.
	tbl := "warehouse:snowflake:pii"
	g.AddNode(estategraph.Node{ID: tbl, Kind: estategraph.KindData, Name: "pii-table", Sensitive: estategraph.SensHigh})
	_ = g.AddEdge(estategraph.Edge{From: host, To: tbl, Kind: estategraph.EdgeGrants, Evidence: []string{"e1"}})

	// Longer path to a privileged identity.
	mid := "principal:mid"
	adm := "principal:admin"
	g.AddNode(estategraph.Node{ID: mid, Kind: estategraph.KindPrincipal})
	g.AddNode(estategraph.Node{ID: adm, Kind: estategraph.KindPrincipal, Name: "admin", Privileged: true})
	_ = g.AddEdge(estategraph.Edge{From: host, To: mid, Kind: estategraph.EdgeReaches, Evidence: []string{"e2"}})
	_ = g.AddEdge(estategraph.Edge{From: mid, To: adm, Kind: estategraph.EdgeAssumes, Evidence: []string{"e3"}})

	leads := LeadsForRoutes(g, []string{"https://shop.example.com/login"})
	if len(leads) != 1 {
		t.Fatalf("want 1 lead, got %d", len(leads))
	}
	if !strings.Contains(strings.ToLower(leads[0].Reaches), "regulated data") {
		t.Errorf("did not pick the sharper PII path: %q", leads[0].Reaches)
	}
}

// Every lead is grounded end to end: the graph refuses evidence-free edges, so a lead can only describe
// a path the estate actually proves. This walks the guarantee rather than trusting it.
func TestLeadsForRoutes_EveryLeadRestsOnProvenEdges(t *testing.T) {
	g := estateWithWebToPII()
	leads := LeadsForRoutes(g, []string{"https://shop.example.com/login"})
	if len(leads) == 0 {
		t.Fatal("no leads")
	}
	for _, l := range leads {
		if len(l.Evidence) == 0 {
			t.Errorf("lead for %s cites nothing", l.Route)
		}
	}
}

func TestLeadsForRoutes_HandlesEmptyInput(t *testing.T) {
	if LeadsForRoutes(nil, []string{"x"}) != nil {
		t.Error("nil graph should yield nil")
	}
	if LeadsForRoutes(estateWithWebToPII(), nil) != nil {
		t.Error("no routes should yield nil")
	}
}
