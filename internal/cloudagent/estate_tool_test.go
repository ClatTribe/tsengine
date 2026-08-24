package cloudagent

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// The ≤12-tool cap (CLAUDE.md §2.6) is the reason estate_context is ONE tool and not three.
// Past ~12 hands, tool-use accuracy degrades — so this is a real ceiling, not a style rule.
func TestToolCatalogStaysWithinTheCap(t *testing.T) {
	if n := len(tools()); n > 12 {
		t.Errorf("cloud tool catalog is %d — past the ≤12 cap that keeps tool-use accurate", n)
	}
}

func estateFixture() *estategraph.Graph {
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: "secret:akia1", Kind: estategraph.KindSecret, Name: "AKIA1",
		Surfaces: []string{"code", "cloud"}, Public: true, Evidence: []string{"f-leak"}})
	g.AddNode(estategraph.Node{ID: "code:repo/app.py", Kind: estategraph.KindCode, Name: "app.py",
		Surfaces: []string{"code"}})
	g.AddNode(estategraph.Node{ID: "cloud:s3/pii", Kind: estategraph.KindData, Name: "customer-PII",
		Surfaces: []string{"cloud"}, Sensitive: estategraph.SensHigh})
	_ = g.AddEdge(estategraph.Edge{From: "secret:akia1", To: "code:repo/app.py",
		Kind: estategraph.EdgeLeakedIn, Evidence: []string{"f-leak"}, Why: "committed in app.py"})
	_ = g.AddEdge(estategraph.Edge{From: "secret:akia1", To: "cloud:s3/pii",
		Kind: estategraph.EdgeGrants, Evidence: []string{"f-bucket"}, Why: "the key can read the bucket"})
	return g
}

// The pivot: from a cloud-side foothold the agent can now see the CODE origin and the crown it
// reaches — with the evidence for each hop, so it can cite them in record_issue.
func TestEstateContext_PivotsAcrossSurfaces(t *testing.T) {
	cc := &Context{Estate: estateFixture()}
	out := tEstate(cc, map[string]any{"id": "secret:akia1"})

	for _, want := range []string{
		"cross-surface bridge", // two surfaces asserting one node is the headline fact
		"cloud + code",         // named, so the agent knows WHICH surfaces
		"code:repo/app.py",     // the origin it could not previously follow
		"cloud:s3/pii",         // what it reaches
		"[CROWN]",              // flagged, so the agent knows it matters
		"evidence: f-leak",     // citable in record_issue
		"evidence: f-bucket",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("estate_context output missing %q\n---\n%s", want, out)
		}
	}
}

// HONEST DEGRADATION: with no estate composed, the tool says the graph is unavailable. It must
// NOT read as "the estate is empty" — "we did not look" and "there is nothing" are different
// answers, and conflating them is how an agent concludes a clean estate from missing data.
func TestEstateContext_UnavailableIsNotEmpty(t *testing.T) {
	out := tEstate(&Context{}, map[string]any{"id": "secret:akia1"})
	if !strings.Contains(out, "not available") {
		t.Errorf("a missing estate graph must say so, got %q", out)
	}
	for _, mustNot := range []string{"no such", "empty", "nothing found"} {
		if strings.Contains(strings.ToLower(out), mustNot) {
			t.Errorf("unavailable must not read as absence (%q): %s", mustNot, out)
		}
	}
}

// An unknown id is refused rather than fuzzy-matched: a fabricated node is a fabricated pivot.
func TestEstateContext_UnknownIDIsRefused(t *testing.T) {
	out := tEstate(&Context{Estate: estateFixture()}, map[string]any{"id": "secret:doesnotexist"})
	if !strings.HasPrefix(out, "ERROR:") {
		t.Errorf("an unknown node id must be refused, got %q", out)
	}
}

// chokeFixture: two internet→crown routes that BOTH pass through cloud:role/etl, which is
// therefore the choke point. Each route crosses surfaces (web → code → cloud edges).
func chokeFixture() *estategraph.Graph {
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: estategraph.InternetID, Kind: estategraph.KindNetwork, Public: true})
	g.AddNode(estategraph.Node{ID: "web:app", Kind: estategraph.KindResource, Name: "app", Surfaces: []string{"web"}, Public: true})
	g.AddNode(estategraph.Node{ID: "cloud:role/etl", Kind: estategraph.KindPrincipal, Name: "etl", Surfaces: []string{"cloud"}})
	g.AddNode(estategraph.Node{ID: "cloud:s3/pii", Kind: estategraph.KindData, Name: "customer-PII", Surfaces: []string{"cloud"}, Sensitive: estategraph.SensHigh})
	g.AddNode(estategraph.Node{ID: "cloud:rds/db", Kind: estategraph.KindData, Name: "prod-db", Surfaces: []string{"cloud"}, Sensitive: estategraph.SensHigh})
	_ = g.AddEdge(estategraph.Edge{From: estategraph.InternetID, To: "web:app", Kind: estategraph.EdgeReaches, Surface: "web", Evidence: []string{"f-exposed"}, Why: "public"})
	_ = g.AddEdge(estategraph.Edge{From: "web:app", To: "cloud:role/etl", Kind: estategraph.EdgeAssumes, Surface: "code", Evidence: []string{"f-oidc"}, Why: "workflow assumes the role"})
	_ = g.AddEdge(estategraph.Edge{From: "cloud:role/etl", To: "cloud:s3/pii", Kind: estategraph.EdgeGrants, Surface: "cloud", Evidence: []string{"f-s3"}, Why: "reads the bucket"})
	_ = g.AddEdge(estategraph.Edge{From: "cloud:role/etl", To: "cloud:rds/db", Kind: estategraph.EdgeGrants, Surface: "cloud", Evidence: []string{"f-rds"}, Why: "reads the db"})
	return g
}

func TestEstateContext_ChokePoints(t *testing.T) {
	cc := &Context{Estate: chokeFixture()}
	out := tEstate(cc, map[string]any{"chokepoints": true})
	if !strings.Contains(out, "cloud:role/etl") {
		t.Errorf("the shared interior node must be reported as the choke point:\n%s", out)
	}
	if !strings.Contains(out, "Highest-leverage") {
		t.Errorf("chokepoints view should render the leverage heading:\n%s", out)
	}
	// The id-alias form works too.
	if out2 := tEstate(cc, map[string]any{"id": "chokepoints"}); !strings.Contains(out2, "cloud:role/etl") {
		t.Errorf("estate_context(id:\"chokepoints\") should also render the view:\n%s", out2)
	}
}

// No cross-surface choke point → an honest "each path is separate work", never a promoted node.
func TestEstateContext_ChokePoints_NoneIsHonest(t *testing.T) {
	cc := &Context{Estate: estateFixture()} // no InternetID entry → no internet→crown routes
	out := tEstate(cc, map[string]any{"chokepoints": true})
	if !strings.Contains(out, "No cross-surface choke point") {
		t.Errorf("an estate with no shared route must say so, not invent a choke point:\n%s", out)
	}
}
