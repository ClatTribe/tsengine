package estateingest

import (
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

// ghoidc.go bridges the CI surface into the estate graph: a GitHub repository that can
// assume an AWS role is a real move an attacker can make, and until now the graph could
// not see it.
//
// This is the wedge edge. Code→cloud bridges already existed for a LEAKED CREDENTIAL —
// a secret committed by mistake. This one needs no mistake at all: the trust is
// deliberate infrastructure, working exactly as configured, and the question is only
// whether it is scoped to what the team intended. An attacker who can land a workflow
// in a trusted repository gets the role legitimately, with no secret to steal.
//
// THE EDGE IS EdgeAssumes AND THE DIRECTION IS repo → role, because that is the move:
// the repository becomes the role. Reversing it would render a path that reads
// backwards to anyone following it.
//
// GROUNDED (§10). An edge is emitted only for a trust we actually READ and a subject we
// could actually PIN:
//
//   - a wildcard subject names no single repository, so there is no repository node to
//     attach — it produces the role node and its weakness findings, not an invented
//     edge to a repo that does not exist. This is the same refusal estateingest already
//     makes for a leaked key with no matching principal.
//   - an unparsed trust policy produces nothing.
//
// The evidence each edge cites is the trust policy statement itself, via the finding ids
// the caller supplies — the trust IS the proof, and a reader can re-read it.

// GitHubOIDCTrust is one observed repo→role trust, already analysed.
type GitHubOIDCTrust struct {
	// Repository is the exact "owner/repo" the trust pins. Empty when the subject
	// wildcards, which is why the caller cannot fabricate one.
	Repository string
	RoleARN    string
	RoleName   string
	Privileged bool
	// Evidence are the finding ids (or observation refs) proving this trust exists.
	Evidence []string
	// Why is the human sentence: which subject pattern permitted it.
	Why string
}

// GitHubOIDC converts observed CI→cloud trusts into a subgraph.
//
// Roles are emitted whether or not a repository could be pinned, because the role is
// real either way; only the EDGE requires a pinned repository.
func GitHubOIDC(trusts []GitHubOIDCTrust, at time.Time) *estategraph.Graph {
	g := estategraph.New()
	for _, t := range trusts {
		if t.RoleARN == "" || len(t.Evidence) == 0 {
			// No role to speak of, or nothing proving the trust. estategraph would refuse
			// the edge anyway; refusing here keeps the reason legible.
			continue
		}
		roleID := estategraph.Canonical(SurfaceCloud, t.RoleARN)
		g.AddNode(estategraph.Node{
			ID: roleID, Kind: estategraph.KindPrincipal, Name: nameOr(t.RoleName, t.RoleARN),
			Surfaces: []string{SurfaceCloud}, Privileged: t.Privileged,
			Evidence: t.Evidence, ObservedAt: at,
		})

		if t.Repository == "" {
			// A wildcard trust: real, reported by its own finding, but there is no single
			// repository to draw an edge from. Inventing one would send a reader to sever a
			// path between a role and a repo that was never named.
			continue
		}
		repoID := estategraph.Canonical(SurfaceCode, t.Repository)
		g.AddNode(estategraph.Node{
			ID: repoID, Kind: estategraph.KindCode, Name: t.Repository,
			Surfaces: []string{SurfaceCode}, ObservedAt: at,
		})
		_ = g.AddEdge(estategraph.Edge{
			From: repoID, To: roleID, Kind: estategraph.EdgeAssumes,
			Evidence: t.Evidence, Surface: SurfaceCode, ObservedAt: at,
			Why: whyOr(t.Why, "a GitHub Actions workflow in "+t.Repository+
				" can assume this role via OIDC — no stored credential is involved"),
		})
	}
	return g
}

// TrustsFrom derives the pinned repo→role trusts from an analysed trust policy. Only
// EXACT subject pins yield a repository; a wildcard yields a trust with none, so the
// role still enters the graph while the edge does not.
func TrustsFrom(an ghoidc.Analysis, roleARN, roleName string, privileged bool, evidence []string) []GitHubOIDCTrust {
	if !an.Parsed || !an.TrustsGitHub {
		return nil
	}
	seen := map[string]bool{}
	var out []GitHubOIDCTrust
	for _, st := range an.Statements {
		for _, c := range st.Subjects {
			if c.Wildcard() {
				continue
			}
			repo := ghoidc.RepositoryOfSubject(c.Value)
			if repo == "" || seen[repo] {
				continue
			}
			seen[repo] = true
			out = append(out, GitHubOIDCTrust{
				Repository: repo, RoleARN: roleARN, RoleName: roleName,
				Privileged: privileged, Evidence: evidence,
				Why: "the role's trust policy pins " + c.Op + " " + c.Value,
			})
		}
	}
	if len(out) == 0 {
		// GitHub is trusted but no single repository is named (wildcard, or pinned via
		// another claim). The role belongs in the graph; the edge does not.
		out = append(out, GitHubOIDCTrust{
			RoleARN: roleARN, RoleName: roleName, Privileged: privileged, Evidence: evidence,
		})
	}
	return out
}

func whyOr(why, fallback string) string {
	if why == "" {
		return fallback
	}
	return why
}
