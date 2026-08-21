package estateingest

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

func ctl(login, org, repo string, admin bool) GitHubControl {
	return GitHubControl{Login: login, Org: org, Repo: repo, Admin: admin, Evidence: []string{"snap-1"}}
}

func TestGitHubIdentity_AssertedLinkDrawsThePersonToCodeEdge(t *testing.T) {
	r := GitHubIdentity(
		[]IdentityLink{{Email: "alice@acme.com", Login: "alice-acme", Source: LinkSourceOktaSCIM}},
		[]GitHubControl{ctl("alice-acme", "acme", "", true)}, ciNow)

	person := estategraph.Canonical("identity", "alice@acme.com")
	out := r.Graph.Out(person)
	if len(out) != 1 || out[0].Kind != estategraph.EdgeOwns {
		t.Fatalf("want person --owns--> org, got %+v", out)
	}
	if r.Linked != 1 || len(r.UnlinkedLogins) != 0 || r.ChainBroken != "" {
		t.Fatalf("a fully linked estate reports no break, got %+v", r)
	}
	if n := r.Graph.Nodes[person]; n == nil || !n.Privileged {
		t.Fatal("an org owner's privilege must reach the graph")
	}
}

// THE REFUSAL. Nothing in either system says alice@acme.com is @alice-acme. A wrong
// merge produces a confident WRONG path, not a missing one.
func TestGitHubIdentity_RefusesToGuessFromNameResemblance(t *testing.T) {
	r := GitHubIdentity(nil, []GitHubControl{ctl("alice-acme", "acme", "", true)}, ciNow)
	if len(r.Graph.Edges) != 0 {
		t.Fatal("with no asserted mapping, no person→code edge may exist")
	}
	if len(r.UnlinkedLogins) != 1 || r.UnlinkedLogins[0] != "alice-acme" {
		t.Fatalf("the unlinked account must be NAMED, not silently dropped: %+v", r.UnlinkedLogins)
	}
	if r.ChainBroken == "" {
		t.Fatal("a broken chain must say so — 'we could not connect this' and 'this person has no access' are different facts")
	}
	if !strings.Contains(r.ChainBroken, "SCIM") || !strings.Contains(r.ChainBroken, "SAML") {
		t.Fatal("the break must name the integration that closes it, or it is a complaint not a finding")
	}
}

// An unattributed link is indistinguishable from a guess, so it is refused.
func TestGitHubIdentity_RefusesAnUnattributedOrUnknownSource(t *testing.T) {
	for _, src := range []string{"", "hr_spreadsheet", "fuzzy_match"} {
		r := GitHubIdentity(
			[]IdentityLink{{Email: "a@acme.com", Login: "a", Source: src}},
			[]GitHubControl{ctl("a", "acme", "", true)}, ciNow)
		if r.Linked != 0 || len(r.Graph.Edges) != 0 {
			t.Fatalf("source %q must be refused, not softened", src)
		}
	}
}

// GitHub logins are case-preserving but not case-sensitive. That is a documented
// platform fact, not a resemblance judgement, so matching across case is correct.
func TestGitHubIdentity_LoginMatchIsCaseInsensitive(t *testing.T) {
	r := GitHubIdentity(
		[]IdentityLink{{Email: "a@acme.com", Login: "Alice-Acme", Source: LinkSourceGitHubSAML}},
		[]GitHubControl{ctl("alice-acme", "acme", "", false)}, ciNow)
	if r.Linked != 1 {
		t.Fatal("one GitHub account differing only in case is the same account")
	}
}

func TestGitHubIdentity_ControlWithoutEvidenceIsRefused(t *testing.T) {
	r := GitHubIdentity(
		[]IdentityLink{{Email: "a@acme.com", Login: "a", Source: LinkSourceOktaSCIM}},
		[]GitHubControl{{Login: "a", Org: "acme", Admin: true}}, ciNow)
	if len(r.Graph.Edges) != 0 {
		t.Fatal("estategraph refuses an unevidenced edge; so must the converter")
	}
}

// THE WHOLE CHAIN. This is the sentence the product exists to say, and it must be
// traversable in one graph rather than assembled by a human across four screens.
func TestFullChain_PersonToRepositoryToRoleIsOneTraversal(t *testing.T) {
	person := estategraph.Canonical("identity", "alice@acme.com")
	roleARN := "arn:aws:iam::123456789012:role/prod-deploy"
	roleID := estategraph.Canonical(SurfaceCloud, roleARN)

	// Hop 1: the human controls the repository (asserted by Okta SCIM).
	id := GitHubIdentity(
		[]IdentityLink{{Email: "alice@acme.com", Login: "alice-acme", Source: LinkSourceOktaSCIM}},
		[]GitHubControl{ctl("alice-acme", "acme", "api", true)}, ciNow)

	// Hop 2: the repository assumes the AWS role (asserted by the trust policy).
	an := ghoidc.Analyze(ghTrust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	ci := GitHubOIDC(TrustsFrom(an, roleARN, "prod-deploy", true, []string{"f-oidc"}), ciNow)

	g := estategraph.New()
	g.Merge(id.Graph)
	g.Merge(ci)

	paths, _ := g.PathsFrom(person, func(n *estategraph.Node) bool { return n.ID == roleID }, 5, 10)
	if len(paths) == 0 {
		t.Fatal("the person must reach the production role by traversal — this is the wedge sentence, " +
			"and if it needs a human to assemble it across screens the product has not said it")
	}
	if len(paths[0].Edges) != 2 {
		t.Fatalf("want person→repo→role in two hops, got %d", len(paths[0].Edges))
	}
	for _, e := range paths[0].Edges {
		if len(e.Evidence) == 0 {
			t.Fatal("every hop of a rendered path must carry its proof")
		}
	}
}

// The counterpart: without the identity assertion, the repo→role hop still stands but
// the chain does NOT reach back to a person. That is the honest degradation.
func TestFullChain_WithoutTheIdentityAssertionTheChainStopsAtTheRepository(t *testing.T) {
	roleARN := "arn:aws:iam::1:role/prod"
	an := ghoidc.Analyze(ghTrust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	g := estategraph.New()
	g.Merge(GitHubIdentity(nil, []GitHubControl{ctl("alice-acme", "acme", "api", true)}, ciNow).Graph)
	g.Merge(GitHubOIDC(TrustsFrom(an, roleARN, "prod", true, []string{"f-x"}), ciNow))

	person := estategraph.Canonical("identity", "alice@acme.com")
	if _, ok := g.Nodes[person]; ok {
		t.Fatal("no assertion linked this person — they must not appear in the graph at all")
	}
	repoID := estategraph.Canonical(SurfaceCode, "acme/api")
	if len(g.Out(repoID)) != 1 {
		t.Fatal("the repo→role hop is independently proven and must survive the missing identity link")
	}
}
