package productscope

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func web(id, t string) platform.Asset  { return platform.Asset{ID: id, Type: "web_application", Target: t} }
func api(id, t string) platform.Asset  { return platform.Asset{ID: id, Type: "api", Target: t} }
func repo(id, t string) platform.Asset { return platform.Asset{ID: id, Type: "repository", Target: t} }
func aws(id, acct string) platform.Asset {
	return platform.Asset{ID: id, Type: "cloud_account", Target: "aws", Meta: map[string]string{"account_id": acct}}
}

// deployGraph builds the estate edge ghoidc produces: a repo's workflows can assume a role.
func deployGraph(t *testing.T, ownerRepo, roleARN string) *estategraph.Graph {
	t.Helper()
	g := estategraph.New()
	from := estategraph.Canonical("code", ownerRepo)
	to := estategraph.Canonical("cloud", roleARN)
	g.AddNode(estategraph.Node{ID: from, Kind: estategraph.KindCode})
	g.AddNode(estategraph.Node{ID: to, Kind: estategraph.KindPrincipal})
	if err := g.AddEdge(estategraph.Edge{From: from, To: to, Kind: estategraph.EdgeAssumes,
		Evidence: []string{"f-oidc-1"}, Why: "OIDC trust pins the repository"}); err != nil {
		t.Fatal(err)
	}
	return g
}

func hasLink(ls []Link, a, b string, k LinkKind) bool {
	if b < a {
		a, b = b, a
	}
	for _, l := range ls {
		if l.A == a && l.B == b && l.Kind == k {
			return true
		}
	}
	return false
}

func TestSharedDomain_LinksSameRegisteredDomain(t *testing.T) {
	ls := Links([]platform.Asset{web("w1", "https://app.acme.com"), api("a1", "https://api.acme.com/v1")}, nil)
	if !hasLink(ls, "w1", "a1", LinkSharedDomain) {
		t.Fatalf("app.acme.com and api.acme.com share acme.com: %+v", ls)
	}
	if ls[0].Evidence[0] != "registered-domain:acme.com" {
		t.Fatalf("evidence must name the registered domain: %+v", ls[0].Evidence)
	}
}

// Two strangers on the same hosting platform must never be joined: the public-suffix list's private
// section makes each *.vercel.app its own registered domain.
func TestSharedDomain_NeverJoinsStrangersOnSharedHosting(t *testing.T) {
	ls := Links([]platform.Asset{web("w1", "https://foo.vercel.app"), web("w2", "https://bar.vercel.app"),
		web("w3", "https://x.herokuapp.com"), web("w4", "https://y.herokuapp.com")}, nil)
	if len(ls) != 0 {
		t.Fatalf("shared-hosting subdomains must not link: %+v", ls)
	}
}

func TestSharedDomain_IgnoresIPsAndInfrastructure(t *testing.T) {
	ls := Links([]platform.Asset{web("w1", "http://10.0.0.1"), web("w2", "http://10.0.0.1:8080"),
		repo("r1", "https://github.com/acme/app"), repo("r2", "https://github.com/acme/web")}, nil)
	if len(ls) != 0 {
		t.Fatalf("IPs are not registered domains and repos are not linked by name: %+v", ls)
	}
}

func TestCIDeploysTo_LinksRepoToItsAccount(t *testing.T) {
	g := deployGraph(t, "acme/api", "arn:aws:iam::123456789012:role/deploy")
	ls := Links([]platform.Asset{repo("r1", "https://github.com/Acme/API"), aws("c1", "123456789012")}, g)
	if !hasLink(ls, "r1", "c1", LinkCIDeploysTo) {
		t.Fatalf("the repo's workflow assumes a role in the connected account: %+v", ls)
	}
	if ls[0].Evidence[0] != "f-oidc-1" {
		t.Fatalf("the link must carry the edge's own evidence: %+v", ls[0].Evidence)
	}
}

// A GitLab project with the same path is a DIFFERENT repository; joining it to a GitHub trust would
// fabricate a deploy relationship.
func TestCIDeploysTo_RefusesNonGitHubPathCollision(t *testing.T) {
	g := deployGraph(t, "acme/api", "arn:aws:iam::123456789012:role/deploy")
	ls := Links([]platform.Asset{repo("r1", "https://gitlab.com/acme/api"), aws("c1", "123456789012")}, g)
	if len(ls) != 0 {
		t.Fatalf("a gitlab.com URL must not map to the GitHub owner/repo node: %+v", ls)
	}
}

func TestCIDeploysTo_RoleInUnconnectedAccountLinksNothing(t *testing.T) {
	g := deployGraph(t, "acme/api", "arn:aws:iam::999999999999:role/deploy")
	ls := Links([]platform.Asset{repo("r1", "https://github.com/acme/api"), aws("c1", "123456789012")}, g)
	if len(ls) != 0 {
		t.Fatalf("a role in an account the tenant did not connect has no asset to join: %+v", ls)
	}
}

// A human who can reach two repositories must not merge them: people are hubs, not deploy links.
func TestHumanIdentityIsNotALink(t *testing.T) {
	g := estategraph.New()
	person := estategraph.Canonical("identity", "cto@acme.com")
	for _, r := range []string{"acme/one", "acme/two"} {
		n := estategraph.Canonical("code", r)
		g.AddNode(estategraph.Node{ID: n, Kind: estategraph.KindCode})
		g.AddNode(estategraph.Node{ID: person, Kind: estategraph.KindPrincipal})
		if err := g.AddEdge(estategraph.Edge{From: person, To: n, Kind: estategraph.EdgeOwns, Evidence: []string{"idp"}}); err != nil {
			t.Fatal(err)
		}
	}
	ls := Links([]platform.Asset{repo("r1", "https://github.com/acme/one"), repo("r2", "https://github.com/acme/two")}, g)
	if len(ls) != 0 {
		t.Fatalf("a person who owns two repos does not make them one product: %+v", ls)
	}
}

func TestPropose_OnlyCustomerFacingGroupsBecomeProducts(t *testing.T) {
	g := deployGraph(t, "acme/api", "arn:aws:iam::123456789012:role/deploy")
	assets := []platform.Asset{
		web("w1", "https://app.acme.com"), api("a1", "https://api.acme.com"),
		repo("r1", "https://github.com/acme/api"), aws("c1", "123456789012"),
		repo("r2", "https://github.com/acme/scripts"),
	}
	res := Propose(assets, Links(assets, g), nil, nil)
	if len(res.Proposals) != 1 || res.Proposals[0].Name != "acme.com" {
		t.Fatalf("want exactly one proposed product acme.com: %+v", res.Proposals)
	}
	if got := res.Proposals[0].AssetIDs; len(got) != 2 {
		t.Fatalf("proposal holds the two customer-facing assets: %v", got)
	}
	// The repo+account pair is PROVEN to belong together but not to a product: an unassigned GROUP,
	// never a second product. The unlinked repo is its own unassigned group.
	if len(res.Unassigned) != 2 {
		t.Fatalf("want 2 unassigned groups (r1+c1 linked, r2 alone): %+v", res.Unassigned)
	}
	var pair bool
	for _, g := range res.Unassigned {
		if len(g.AssetIDs) == 2 && len(g.Links) == 1 && g.Links[0].Kind == LinkCIDeploysTo {
			pair = true
		}
	}
	if !pair {
		t.Fatalf("the deploy-linked repo+account must be reported as one group with its reason: %+v", res.Unassigned)
	}
}

func TestPropose_SuggestsLinkedAssetForConfirmedProductButNeverAddsIt(t *testing.T) {
	assets := []platform.Asset{web("w1", "https://app.acme.com"), api("a1", "https://api.acme.com")}
	products := []platform.Product{{ID: "p1", Name: "Acme", AssetIDs: []string{"w1"}}}
	res := Propose(assets, Links(assets, nil), products, nil)
	if len(res.Suggestions) != 1 || res.Suggestions[0].ProductID != "p1" || res.Suggestions[0].AssetID != "a1" {
		t.Fatalf("api.acme.com is linked into the confirmed product and should be SUGGESTED: %+v", res.Suggestions)
	}
	if len(res.Proposals) != 0 || len(res.Unassigned) != 0 {
		t.Fatalf("a suggested asset must not also appear as a proposal or unassigned: %+v", res)
	}
	if len(products[0].AssetIDs) != 1 {
		t.Fatal("Propose must never mutate a confirmed product")
	}
}

func TestPropose_OutOfScopeAssetsDisappearFromEverything(t *testing.T) {
	assets := []platform.Asset{web("w1", "https://app.acme.com"), web("w2", "https://www.acme.com")}
	out := map[string]platform.ScopeExclusion{"w2": {By: "cto", Reason: "marketing site"}}
	res := Propose(assets, Links(assets, nil), nil, out)
	if len(res.Proposals) != 1 || len(res.Proposals[0].AssetIDs) != 1 || res.Proposals[0].AssetIDs[0] != "w1" {
		t.Fatalf("the excluded marketing site must not be proposed: %+v", res.Proposals)
	}
}

func TestPropose_IsDeterministic(t *testing.T) {
	assets := []platform.Asset{web("w3", "https://c.example.org"), web("w1", "https://a.acme.com"),
		web("w2", "https://b.acme.com"), repo("r1", "https://github.com/acme/x")}
	first := Propose(assets, Links(assets, nil), nil, nil)
	for i := 0; i < 20; i++ {
		again := Propose(assets, Links(assets, nil), nil, nil)
		if len(again.Proposals) != len(first.Proposals) || again.Proposals[0].Name != first.Proposals[0].Name {
			t.Fatal("the same inputs must propose the same products in the same order")
		}
	}
}

func TestAccountOfPrincipalAndRepoNode(t *testing.T) {
	if got := AccountOfPrincipal("cloud:arn:aws:iam::123456789012:role/x"); got != "123456789012" {
		t.Fatalf("aws account: %q", got)
	}
	if got := AccountOfPrincipal("principal:ci@my-proj.iam.gserviceaccount.com"); got != "my-proj" {
		t.Fatalf("gcp project: %q", got)
	}
	if got := AccountOfPrincipal("principal:alice@acme.com"); got != "" {
		t.Fatalf("a human email has no account: %q", got)
	}
	if got := GitHubRepoNode("https://github.com/Acme/API.git"); got != "code:acme/api" {
		t.Fatalf("repo node: %q", got)
	}
}
