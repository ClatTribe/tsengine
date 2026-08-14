package estategraph

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── THE INVARIANT THIS PACKAGE EXISTS TO HOLD ───────────────────────────────────────────────────
//
// The graph is the agent's ground truth. An edge in it that nobody proved is a hallucination with a
// data structure around it, and an agent traversing one would report a path that does not exist.

func TestAddEdge_RefusesAnEdgeWithNoEvidence(t *testing.T) {
	g := New()
	for _, ev := range [][]string{nil, {}, {""}, {"  "}} {
		err := g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeReaches, Evidence: ev})
		if !errors.Is(err, ErrNoEvidence) {
			t.Errorf("evidence %q accepted (err=%v) — an agent could then walk a hop nobody proved", ev, err)
		}
	}
	if len(g.Edges) != 0 {
		t.Fatalf("graph kept %d unproven edges", len(g.Edges))
	}
}

func TestAddEdge_AcceptsAProvenEdge(t *testing.T) {
	g := New()
	if err := g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeReaches, Evidence: []string{"f-1"}}); err != nil {
		t.Fatalf("a proven edge was refused: %v", err)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(g.Edges))
	}
	// Endpoints must materialise, so a surface can assert an edge before the node's detector runs.
	if g.Nodes["a"] == nil || g.Nodes["b"] == nil {
		t.Error("edge endpoints were not created as nodes")
	}
}

// Merge must not be a way around the invariant. If it were, every surface would have a silent bypass —
// which is exactly how the Bridges []string workaround happened in the first place.
func TestMerge_DoesNotSmuggleUnprovenEdges(t *testing.T) {
	src := New()
	// Construct the bad edge directly in the struct, bypassing AddEdge — simulating a surface that
	// built its subgraph carelessly.
	src.Nodes["a"] = &Node{ID: "a"}
	src.Nodes["b"] = &Node{ID: "b"}
	src.Edges = append(src.Edges, Edge{From: "a", To: "b", Kind: EdgeReaches}) // no evidence

	dst := New()
	dst.Merge(src)
	if len(dst.Edges) != 0 {
		t.Error("Merge smuggled in an edge with no evidence — the invariant has a back door")
	}
	if len(dst.Nodes) != 2 {
		t.Errorf("nodes = %d, want the 2 merged nodes (nodes may legitimately lack evidence)", len(dst.Nodes))
	}
}

func TestAddEdge_RejectsDegenerateMoves(t *testing.T) {
	g := New()
	ev := []string{"f-1"}
	if err := g.AddEdge(Edge{From: "a", To: "a", Kind: EdgeReaches, Evidence: ev}); err == nil {
		t.Error("a self-edge was accepted — reaching yourself is not a move")
	}
	if err := g.AddEdge(Edge{From: "", To: "b", Kind: EdgeReaches, Evidence: ev}); err == nil {
		t.Error("an edge with no source was accepted")
	}
}

// ─── IDENTITY RESOLUTION: THE CROSS-SURFACE PREMISE ──────────────────────────────────────────────

// THE ONE THAT MATTERS. A Snowflake grantee and a GCP service account are the same principal. If these
// do not converge, the estate graph is several graphs in a trenchcoat and nothing cross-surface works.
func TestCanonical_WarehouseGranteeJoinsTheCloudPrincipal(t *testing.T) {
	fromWarehouse := Canonical("warehouse", "etl@acme.iam.gserviceaccount.com")
	fromCloud := Canonical("cloud", "ETL@acme.iam.gserviceaccount.com")
	if fromWarehouse != fromCloud {
		t.Fatalf("the same service account got two ids:\n  warehouse: %s\n  cloud:     %s", fromWarehouse, fromCloud)
	}
	if !strings.HasPrefix(fromWarehouse, "principal:") {
		t.Errorf("id = %q, want the shared principal namespace (not a per-surface one)", fromWarehouse)
	}
}

func TestCanonical_JoinsKnownIdentifierFormats(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"arn case", "arn:aws:iam::1:role/App", "ARN:AWS:IAM::1:ROLE/APP"},
		{"url scheme and slash", "https://api.acme.com/", "http://api.acme.com"},
		{"human email case", "Alice@acme.com", "alice@acme.com"},
	} {
		if x, y := Canonical("a", tc.a), Canonical("b", tc.b); x != y {
			t.Errorf("%s: %q and %q did not converge (%s vs %s)", tc.name, tc.a, tc.b, x, y)
		}
	}
}

// THE REFUSAL. A wrong merge fabricates a path — it would send someone to sever a link that never
// existed while the real route stayed open. Two disconnected subgraphs are the honest failure.
func TestCanonical_NeverMergesOnResemblance(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"different accounts", "arn:aws:iam::1:role/App", "arn:aws:iam::2:role/App"},
		{"different domains", "etl@acme.com", "etl@evil.com"},
		{"similar names", "prod-db", "prod-db-2"},
		{"different sa projects", "etl@a.iam.gserviceaccount.com", "etl@b.iam.gserviceaccount.com"},
	} {
		if x, y := Canonical("s", tc.a), Canonical("s", tc.b); x == y {
			t.Errorf("%s: %q and %q were merged into %q — that fabricates a path", tc.name, tc.a, tc.b, x)
		}
	}
}

// An unrecognised identifier keeps its surface namespace rather than being forced into a shared one.
func TestCanonical_UnknownShapesStayInTheirOwnNamespace(t *testing.T) {
	if got := Canonical("warehouse", "analytics.public.customers"); !strings.HasPrefix(got, "warehouse:") {
		t.Errorf("id = %q, want the warehouse namespace — an unjoined node is honest", got)
	}
	if a, b := Canonical("warehouse", "x"), Canonical("code", "x"); a == b {
		t.Error("the same opaque string on two surfaces was joined — that is a guess")
	}
}

// ─── MERGE SEMANTICS ─────────────────────────────────────────────────────────────────────────────

// Sensitivity must only ever RISE. If an unclassified assertion could clear a positive one, a crown
// jewel would silently stop looking like one and every path to it would stop mattering.
func TestAddNode_SensitivityOnlyRises(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "t", Kind: KindData, Sensitive: SensHigh, Surfaces: []string{"warehouse"}})
	g.AddNode(Node{ID: "t", Kind: KindData, Sensitive: SensUnknown, Surfaces: []string{"cloud"}})
	if got := g.Nodes["t"].Sensitive; got != SensHigh {
		t.Errorf("sensitivity = %q after an unclassified re-assert, want high", got)
	}
	if len(g.Nodes["t"].Surfaces) != 2 {
		t.Errorf("surfaces = %v, want both — the cross-surface join is the thing worth seeing", g.Nodes["t"].Surfaces)
	}
}

// Same reasoning for exposure: if one surface SAW it public, a later silent assertion must not clear it.
func TestAddNode_ExposureFlagsNeverClear(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "b", Public: true, Privileged: true})
	g.AddNode(Node{ID: "b"})
	if n := g.Nodes["b"]; !n.Public || !n.Privileged {
		t.Errorf("public=%v privileged=%v — a silent re-assert cleared a positive observation", n.Public, n.Privileged)
	}
}

// The same move asserted by two surfaces is corroboration, not two moves. Duplicates would double-count
// in ChokePoints and manufacture leverage that is not there.
func TestAddEdge_SameMoveFromTwoSurfacesCorroborates(t *testing.T) {
	g := New()
	_ = g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeGrants, Evidence: []string{"f-1"}, Surface: "cloud"})
	_ = g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeGrants, Evidence: []string{"f-2"}, Surface: "warehouse"})
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 corroborated edge", len(g.Edges))
	}
	if len(g.Edges[0].Evidence) != 2 {
		t.Errorf("evidence = %v, want both findings", g.Edges[0].Evidence)
	}
}

// ─── TRAVERSAL: WHAT THE AGENT COULD NOT DO BEFORE ───────────────────────────────────────────────

// The end-to-end shape the whole package is for: a leaked key in code reaches a cloud principal, which
// holds a warehouse grant, which reads a PII table. Three surfaces, one path — and today the Lead would
// only ever see this as a pre-rendered string.
func TestPathsFrom_WalksAcrossThreeSurfaces(t *testing.T) {
	g := New()
	key := Canonical("code", "AKIAIOSFODNN7EXAMPLE")
	sa := Canonical("warehouse", "etl@acme.iam.gserviceaccount.com")
	tbl := Canonical("warehouse", "analytics.public.customers")

	g.AddNode(Node{ID: key, Kind: KindSecret, Surfaces: []string{"code"}})
	g.AddNode(Node{ID: sa, Kind: KindPrincipal, Surfaces: []string{"cloud"}})
	g.AddNode(Node{ID: tbl, Kind: KindData, Sensitive: SensHigh, Surfaces: []string{"warehouse"}})
	for _, e := range []Edge{
		{From: InternetID, To: key, Kind: EdgeLeakedIn, Evidence: []string{"f-gitleaks"}},
		{From: key, To: sa, Kind: EdgeAssumes, Evidence: []string{"f-key-maps"}},
		{From: sa, To: tbl, Kind: EdgeGrants, Evidence: []string{"f-grant"}},
	} {
		if err := g.AddEdge(e); err != nil {
			t.Fatalf("setup edge refused: %v", err)
		}
	}

	paths, _ := g.PathsFrom(InternetID, Crown, 6, 10)
	if len(paths) == 0 {
		t.Fatal("no path from the internet to the PII table — the cross-surface join failed")
	}
	last := paths[0].Nodes[len(paths[0].Nodes)-1]
	if last != tbl {
		t.Errorf("path ends at %q, want the sensitive table %q", last, tbl)
	}
	// Every hop must carry its proof; that is what an agent cites when it reports the path.
	for _, e := range paths[0].Edges {
		if len(e.Evidence) == 0 {
			t.Errorf("hop %s→%s has no evidence", e.From, e.To)
		}
	}
}

func TestPathsFrom_IsBoundedAndReportsTruncation(t *testing.T) {
	g := New()
	// A long chain, deeper than the depth cap.
	prev := InternetID
	for i := 0; i < 10; i++ {
		id := "n" + itoa(i)
		g.AddNode(Node{ID: id, Privileged: true})
		if err := g.AddEdge(Edge{From: prev, To: id, Kind: EdgeReaches, Evidence: []string{"f"}}); err != nil {
			t.Fatal(err)
		}
		prev = id
	}
	_, truncated := g.PathsFrom(InternetID, Crown, 3, 100)
	if !truncated {
		t.Error("hit the depth cap without reporting truncation — a caller would read a partial answer as complete")
	}
}

func TestPathsFrom_DoesNotLoopForever(t *testing.T) {
	g := New()
	ev := []string{"f"}
	_ = g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeReaches, Evidence: ev})
	_ = g.AddEdge(Edge{From: "b", To: "c", Kind: EdgeReaches, Evidence: ev})
	_ = g.AddEdge(Edge{From: "c", To: "a", Kind: EdgeReaches, Evidence: ev}) // cycle
	g.AddNode(Node{ID: "c", Privileged: true})
	done := make(chan bool, 1)
	go func() { g.PathsFrom("a", Crown, 6, 10); done <- true }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PathsFrom did not terminate on a cyclic graph")
	}
}

func TestNeighbors_LetsAnAgentPivot(t *testing.T) {
	g := New()
	ev := []string{"f"}
	_ = g.AddEdge(Edge{From: "a", To: "c", Kind: EdgeReaches, Evidence: ev})
	_ = g.AddEdge(Edge{From: "a", To: "b", Kind: EdgeGrants, Evidence: ev})
	got := g.Neighbors("a")
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Errorf("neighbors = %v, want a stable sorted [b c]", got)
	}
	if n := g.Neighbors("nope"); len(n) != 0 {
		t.Errorf("unknown node returned %v", n)
	}
}

// ─── CHOKE POINTS AS REAL BETWEENNESS ────────────────────────────────────────────────────────────

func TestChokePoints_RankTheSharedInteriorNode(t *testing.T) {
	paths := []Path{
		{Nodes: []string{"internet", "role", "db"}},
		{Nodes: []string{"internet", "role", "bucket"}},
		{Nodes: []string{"internet", "vpn", "wiki"}},
	}
	got := ChokePoints(paths)
	if len(got) != 1 {
		t.Fatalf("choke points = %+v, want only the shared role", got)
	}
	if got[0].ID != "role" || got[0].Paths != 2 {
		t.Errorf("got %+v, want role appearing in 2 paths", got[0])
	}
}

// Endpoints are not choke points: every path starts at the source and ends at the crown, so both would
// rank top on every estate. "Fix the thing being attacked" is not a finding.
func TestChokePoints_ExcludeEndpoints(t *testing.T) {
	paths := []Path{
		{Nodes: []string{"internet", "a", "crown"}},
		{Nodes: []string{"internet", "b", "crown"}},
	}
	for _, cp := range ChokePoints(paths) {
		if cp.ID == "internet" || cp.ID == "crown" {
			t.Errorf("%q ranked as a choke point, but it is an endpoint of every path", cp.ID)
		}
	}
}

func TestChokePoints_SinglePathIsNotLeverage(t *testing.T) {
	if got := ChokePoints([]Path{{Nodes: []string{"internet", "role", "db"}}}); len(got) != 0 {
		t.Errorf("got %+v — appearing in one path is not leverage, it IS the path", got)
	}
}

// A path that revisits a node must not outrank three genuinely distinct routes.
func TestChokePoints_CountOncePerPath(t *testing.T) {
	got := ChokePoints([]Path{{Nodes: []string{"internet", "r", "x", "r", "crown"}}})
	if len(got) != 0 {
		t.Errorf("got %+v — one path counted twice through the same node", got)
	}
}
