package estatedetect

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
)

var now = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// crossSurfaceEstate is the canonical join: an AWS key committed to a repo (the CODE surface)
// is a live IAM role (the CLOUD surface) that reads the customer-PII bucket. gitleaks sees the
// left half, prowler sees the right half, neither sees the sentence.
func crossSurfaceEstate(t *testing.T) *estategraph.Graph {
	t.Helper()
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: estategraph.InternetID, Kind: estategraph.KindNetwork, Name: "internet"})
	g.AddNode(estategraph.Node{ID: "secret:akia123", Kind: estategraph.KindSecret, Name: "AKIA123",
		Surfaces: []string{"code", "cloud"}, Public: true, Evidence: []string{"f-leak"}})
	g.AddNode(estategraph.Node{ID: "code:repo/app.py", Kind: estategraph.KindCode, Name: "app.py",
		Surfaces: []string{"code"}, Evidence: []string{"f-leak"}})
	g.AddNode(estategraph.Node{ID: "cloud:role/deploy", Kind: estategraph.KindPrincipal, Name: "deploy-role",
		Surfaces: []string{"cloud"}, Evidence: []string{"f-role"}})
	g.AddNode(estategraph.Node{ID: "cloud:s3/pii", Kind: estategraph.KindData, Name: "customer-PII",
		Surfaces: []string{"cloud"}, Sensitive: estategraph.SensHigh, Evidence: []string{"f-bucket"}})

	must := func(e estategraph.Edge) {
		t.Helper()
		if err := g.AddEdge(e); err != nil {
			t.Fatalf("edge: %v", err)
		}
	}
	must(estategraph.Edge{From: "secret:akia123", To: "code:repo/app.py", Kind: estategraph.EdgeLeakedIn,
		Surface: "code", Evidence: []string{"f-leak"}, Why: "key committed in app.py"})
	must(estategraph.Edge{From: estategraph.InternetID, To: "secret:akia123", Kind: estategraph.EdgeReaches,
		Surface: "code", Evidence: []string{"f-leak"}, Why: "the repo is public"})
	must(estategraph.Edge{From: "secret:akia123", To: "cloud:role/deploy", Kind: estategraph.EdgeAssumes,
		Surface: "cloud", Evidence: []string{"f-role"}, Why: "the key authenticates as deploy-role"})
	must(estategraph.Edge{From: "cloud:role/deploy", To: "cloud:s3/pii", Kind: estategraph.EdgeGrants,
		Surface: "cloud", Evidence: []string{"f-bucket"}, Why: "deploy-role can read the bucket"})
	return g
}

// THE HEADLINE: the join produces a finding neither surface could produce alone, and it cites
// the findings from BOTH surfaces as its evidence.
func TestDetectsTheCrossSurfaceJoin(t *testing.T) {
	out := Detect(crossSurfaceEstate(t), Options{Now: now})
	if len(out) == 0 {
		t.Fatal("the canonical code→cloud join produced no finding")
	}
	var bridge, path bool
	for _, f := range out {
		switch f.RuleID {
		case "estate::leaked-credential-is-live":
			bridge = true
			// It must cite evidence from BOTH surfaces — that is what makes it derived rather
			// than asserted.
			ev := strings.Join(f.DerivedFrom, ",")
			if !strings.Contains(ev, "f-leak") || !strings.Contains(ev, "f-role") {
				t.Errorf("bridge finding must cite both surfaces' findings, got %v", f.DerivedFrom)
			}
			// The remediation ORDER matters and must be stated: revoke before scrub.
			if !strings.Contains(f.Description, "Revoke the credential in the cloud first") {
				t.Error("must say revoke-then-scrub — scrubbing first leaves a working key out there")
			}
		case "estate::cross-surface-path-to-crown":
			path = true
			if !strings.Contains(f.Description, "customer-PII") {
				t.Errorf("path finding should name what is reached, got %q", f.Description)
			}
		}
	}
	if !bridge {
		t.Error("missing estate::leaked-credential-is-live — the join that no single tool can make")
	}
	if !path {
		t.Error("missing estate::cross-surface-path-to-crown")
	}
}

// SCOPE DISCIPLINE: a path living entirely inside ONE surface is already that surface's finding.
// Reporting it again here is how a correlation layer becomes a second source of the same noise.
func TestSingleSurfacePathIsNotReported(t *testing.T) {
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: estategraph.InternetID, Kind: estategraph.KindNetwork, Name: "internet"})
	g.AddNode(estategraph.Node{ID: "cloud:ec2/web", Kind: estategraph.KindResource, Name: "web", Surfaces: []string{"cloud"}})
	g.AddNode(estategraph.Node{ID: "cloud:role/admin", Kind: estategraph.KindPrincipal, Name: "admin",
		Surfaces: []string{"cloud"}, Privileged: true})
	_ = g.AddEdge(estategraph.Edge{From: estategraph.InternetID, To: "cloud:ec2/web", Kind: estategraph.EdgeReaches,
		Surface: "cloud", Evidence: []string{"f-1"}})
	_ = g.AddEdge(estategraph.Edge{From: "cloud:ec2/web", To: "cloud:role/admin", Kind: estategraph.EdgeRunsAs,
		Surface: "cloud", Evidence: []string{"f-2"}})

	for _, f := range Detect(g, Options{Now: now}) {
		if f.RuleID == "estate::cross-surface-path-to-crown" {
			t.Error("a cloud-only path is cloudgraph's finding — re-reporting it here duplicates it")
		}
	}
}

// A leaked key nobody can tie to a live identity stays the code scanner's finding.
func TestSingleSurfaceSecretIsNotABridge(t *testing.T) {
	g := estategraph.New()
	g.AddNode(estategraph.Node{ID: "secret:akia999", Kind: estategraph.KindSecret, Name: "AKIA999",
		Surfaces: []string{"code"}, Evidence: []string{"f-x"}})
	g.AddNode(estategraph.Node{ID: "cloud:s3/pii", Kind: estategraph.KindData, Name: "pii",
		Sensitive: estategraph.SensHigh, Surfaces: []string{"cloud"}})
	_ = g.AddEdge(estategraph.Edge{From: "secret:akia999", To: "cloud:s3/pii", Kind: estategraph.EdgeGrants,
		Surface: "cloud", Evidence: []string{"f-y"}})
	for _, f := range Detect(g, Options{Now: now}) {
		if f.RuleID == "estate::leaked-credential-is-live" {
			t.Error("a secret seen on only one surface must not be reported as a cross-surface bridge")
		}
	}
}

// An empty or unjoined estate yields nothing — the correct answer for an estate we have only
// seen one surface of, rather than a hedge.
func TestNothingJoinedYieldsNothing(t *testing.T) {
	if out := Detect(estategraph.New(), Options{Now: now}); len(out) != 0 {
		t.Errorf("empty graph produced %d finding(s)", len(out))
	}
	if out := Detect(nil, Options{Now: now}); out != nil {
		t.Error("nil graph must produce nothing")
	}
}

// The choke point is the actionable half: it must name a node MANY routes share, and never an
// endpoint (the crown is what is attacked, not the thing to fix).
func TestChokePointIsInteriorAndOnlyWhenShared(t *testing.T) {
	g := crossSurfaceEstate(t)
	// a second internet entry that funnels through the SAME secret
	g.AddNode(estategraph.Node{ID: "code:repo/other.py", Kind: estategraph.KindCode, Name: "other.py", Surfaces: []string{"code"}})
	_ = g.AddEdge(estategraph.Edge{From: estategraph.InternetID, To: "code:repo/other.py", Kind: estategraph.EdgeReaches,
		Surface: "code", Evidence: []string{"f-leak2"}})
	_ = g.AddEdge(estategraph.Edge{From: "code:repo/other.py", To: "secret:akia123", Kind: estategraph.EdgeStores,
		Surface: "code", Evidence: []string{"f-leak2"}})

	for _, f := range Detect(g, Options{Now: now}) {
		if f.RuleID != "estate::choke-point" {
			continue
		}
		if f.Endpoint == "cloud:s3/pii" || f.Endpoint == estategraph.InternetID {
			t.Errorf("choke point must be interior, got the endpoint %q", f.Endpoint)
		}
		return // found and valid
	}
}
