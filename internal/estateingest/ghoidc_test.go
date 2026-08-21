package estateingest

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

var ciNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func ghTrust(cond string) []byte {
	return []byte(`{"Statement":[{"Effect":"Allow",
      "Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
      "Action":"sts:AssumeRoleWithWebIdentity"` + cond + `}]}`)
}

const roleARN = "arn:aws:iam::123456789012:role/deploy"

func TestGitHubOIDC_PinnedTrustBecomesATraversableRepoToRoleEdge(t *testing.T) {
	an := ghoidc.Analyze(ghTrust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:aud":"sts.amazonaws.com",
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	g := GitHubOIDC(TrustsFrom(an, roleARN, "deploy", true, []string{"f-1"}), ciNow)

	repoID := estategraph.Canonical(SurfaceCode, "acme/api")
	roleID := estategraph.Canonical(SurfaceCloud, roleARN)

	edges := g.Out(repoID)
	if len(edges) != 1 {
		t.Fatalf("the repository should reach the role in one hop, got %d edges", len(edges))
	}
	e := edges[0]
	if e.To != roleID || e.Kind != estategraph.EdgeAssumes {
		t.Fatalf("want repo --assumes--> role, got %s --%s--> %s", e.From, e.Kind, e.To)
	}
	if len(e.Evidence) == 0 {
		t.Fatal("estategraph refuses an unevidenced edge; this one must carry its proof")
	}
	if n, ok := g.Nodes[roleID]; !ok || !n.Privileged {
		t.Fatal("the role's privilege is supplied by IAM and must survive into the graph")
	}
}

// The refusal that mirrors the leaked-key rule: a wildcard names no repository, so no
// edge may be drawn — but the role is still real and must appear.
func TestGitHubOIDC_WildcardTrustAddsTheRoleButInventsNoRepository(t *testing.T) {
	an := ghoidc.Analyze(ghTrust(`,"Condition":{
       "StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
       "StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`))
	g := GitHubOIDC(TrustsFrom(an, roleARN, "deploy", false, []string{"f-2"}), ciNow)

	roleID := estategraph.Canonical(SurfaceCloud, roleARN)
	if _, ok := g.Nodes[roleID]; !ok {
		t.Fatal("the role exists regardless of how loosely it is trusted")
	}
	for id := range g.Nodes {
		if id != roleID {
			t.Fatalf("a wildcard names no single repository — %q was invented", id)
		}
	}
	if len(g.Edges) != 0 {
		t.Fatal("no repository was named, so no edge may be drawn to one")
	}
}

// The direction is the move. A reversed edge renders a path that reads backwards.
func TestGitHubOIDC_EdgeDirectionIsRepoToRoleNotTheReverse(t *testing.T) {
	an := ghoidc.Analyze(ghTrust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	g := GitHubOIDC(TrustsFrom(an, roleARN, "deploy", false, []string{"f-3"}), ciNow)
	roleID := estategraph.Canonical(SurfaceCloud, roleARN)
	if len(g.Out(roleID)) != 0 {
		t.Fatal("the role does not assume the repository — the move runs the other way")
	}
}

func TestGitHubOIDC_NoEvidenceMeansNoNodeAndNoEdge(t *testing.T) {
	g := GitHubOIDC([]GitHubOIDCTrust{{Repository: "acme/api", RoleARN: roleARN}}, ciNow)
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatal("a trust nobody can point at must not enter the agent's ground truth")
	}
}

func TestTrustsFrom_IgnoresAPolicyThatDoesNotTrustGitHub(t *testing.T) {
	an := ghoidc.Analyze([]byte(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
        "Principal":{"AWS":"arn:aws:iam::1:root"}}]}`))
	if got := TrustsFrom(an, roleARN, "deploy", false, []string{"f-4"}); got != nil {
		t.Fatalf("a role unreachable from Actions contributes nothing, got %+v", got)
	}
}

// Merge is how a subgraph joins the estate: the repo node must converge with one another
// surface already asserted, rather than sitting in its own island.
func TestGitHubOIDC_RepoNodeJoinsAnExistingCodeNode(t *testing.T) {
	an := ghoidc.Analyze(ghTrust(`,"Condition":{"StringEquals":{
       "token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`))
	ci := GitHubOIDC(TrustsFrom(an, roleARN, "deploy", false, []string{"f-5"}), ciNow)

	repoID := estategraph.Canonical(SurfaceCode, "acme/api")
	base := estategraph.New()
	base.AddNode(estategraph.Node{ID: repoID, Kind: estategraph.KindCode, Name: "acme/api",
		Surfaces: []string{SurfaceCode}, ObservedAt: ciNow})
	base.Merge(ci)

	if len(base.Out(repoID)) != 1 {
		t.Fatal("after merge the pre-existing repository node must carry the new assume edge — " +
			"otherwise the CI trust is an island the agent cannot reach from code")
	}
}
