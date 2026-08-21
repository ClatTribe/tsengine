package estateingest

import (
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/estategraph"
)

// ghidentity.go closes the last hop of the cross-surface chain: the HUMAN who controls
// the code that reaches the cloud.
//
//	Okta admin without MFA → GitHub org owner → repository → AWS role → customer data
//
// Every hop but the first already exists. FromIdentityFindings makes the person a node,
// GitHubOIDC makes the repository→role edge, and the cloud converters carry it to the
// data. What is missing is the edge from the person to the repository — and it is
// missing for a REASON, not by oversight.
//
// # There is no shared identifier, and we will not invent one
//
// Okta names a person by EMAIL (operate.User.Email). GitHub names them by LOGIN
// (sspm.OrgMember.Login) and does not publish their email. Nothing in either dataset
// says alice@acme.com is @alice-acme — that is a resemblance, and estategraph exists to
// refuse resemblance. A wrong merge here does not produce a missing path; it produces a
// CONFIDENT WRONG ONE, sending someone to revoke the access of a person who never had it
// while the person who does keeps theirs.
//
// So the link must be ASSERTED by a system that actually knows it:
//
//	Okta SCIM app assignment for GitHub  → Okta itself states the mapping
//	GitHub SAML external identity        → GitHub itself states the nameId
//
// With one of those, the edge is drawn. Without, the chain is reported BROKEN and the
// customer is told exactly which integration closes it. A broken chain we can name beats
// a complete-looking chain built on a guess — and unlike a guess, it is fixable.

// IdentityLink is one authoritatively-asserted person↔GitHub-account mapping.
type IdentityLink struct {
	// Email is the workforce identity (Okta / Workspace / M365).
	Email string
	// Login is the GitHub account.
	Login string
	// Source names WHO asserted this mapping, so a reader can weigh it. An empty source
	// is refused: an unattributed link is indistinguishable from a guess.
	Source string
}

// LinkSources are the assertions we accept. Anything else is refused rather than
// silently trusted — the set is small on purpose.
const (
	LinkSourceOktaSCIM   = "okta_scim"   // Okta's own app assignment for GitHub
	LinkSourceGitHubSAML = "github_saml" // GitHub's SAML external identity (nameId)
)

// GitHubControl is one person's authority over a repository or organisation, as observed
// by GitHub itself.
type GitHubControl struct {
	Login string
	// Org is the organisation; Repo is optional. An org owner controls every repository
	// in it, which is why an org-level control is worth an edge of its own.
	Org  string
	Repo string
	// Admin reports org-owner or repo-admin authority.
	Admin bool
	// Evidence proves this control was observed (a finding id, or the SaaS-posture
	// snapshot reference).
	Evidence []string
}

// JoinResult is what could be linked, and — just as importantly — what could not.
type JoinResult struct {
	Graph *estategraph.Graph
	// Linked is how many people were joined to a GitHub account.
	Linked int
	// UnlinkedLogins are GitHub accounts with authority that no assertion mapped to a
	// person. These are the holes in the chain: real authority whose owner we cannot
	// name, so no path through them can be rendered.
	UnlinkedLogins []string
	// ChainBroken explains, in the customer's terms, why the human→code hop is missing
	// and which integration closes it. Empty when nothing was unlinked.
	ChainBroken string
}

// GitHubIdentity draws person→repository/org control edges from authoritative links.
//
// Grounded (§10): an edge is emitted only where an accepted source asserted the mapping
// AND GitHub itself observed the authority. A login nobody mapped contributes no edge and
// is reported in UnlinkedLogins, because "we could not connect this" and "this person has
// no access" are different facts.
func GitHubIdentity(links []IdentityLink, controls []GitHubControl, at time.Time) JoinResult {
	g := estategraph.New()
	res := JoinResult{Graph: g}

	// Index the accepted links by login. Case-insensitive: GitHub logins are
	// case-preserving but not case-sensitive, so "Alice" and "alice" are one account —
	// that is a documented platform fact, not a resemblance judgement.
	byLogin := map[string]IdentityLink{}
	for _, l := range links {
		if !acceptedSource(l.Source) || l.Email == "" || l.Login == "" {
			continue // an unattributed or incomplete link is refused, not softened
		}
		byLogin[strings.ToLower(l.Login)] = l
	}

	seenUnlinked := map[string]bool{}
	for _, c := range controls {
		if c.Login == "" || c.Org == "" || len(c.Evidence) == 0 {
			continue
		}
		link, ok := byLogin[strings.ToLower(c.Login)]
		if !ok {
			if !seenUnlinked[c.Login] {
				seenUnlinked[c.Login] = true
				res.UnlinkedLogins = append(res.UnlinkedLogins, c.Login)
			}
			continue
		}

		person := estategraph.Canonical("identity", link.Email)
		g.AddNode(estategraph.Node{
			ID: person, Kind: estategraph.KindPrincipal, Name: link.Email,
			Surfaces: []string{"identity"}, Privileged: c.Admin,
			Evidence: c.Evidence, ObservedAt: at,
		})

		target, name := c.Org, c.Org
		if c.Repo != "" {
			target, name = c.Org+"/"+c.Repo, c.Org+"/"+c.Repo
		}
		codeID := estategraph.Canonical(SurfaceCode, target)
		g.AddNode(estategraph.Node{
			ID: codeID, Kind: estategraph.KindCode, Name: name,
			Surfaces: []string{SurfaceCode}, ObservedAt: at,
		})
		_ = g.AddEdge(estategraph.Edge{
			From: person, To: codeID, Kind: estategraph.EdgeOwns,
			Evidence: c.Evidence, Surface: "identity", ObservedAt: at,
			Why: link.Email + " is " + authority(c) + " of " + name +
				" (mapped by " + link.Source + ")",
		})
		res.Linked++
	}

	if len(res.UnlinkedLogins) > 0 {
		res.ChainBroken = "no authoritative mapping connects " + countOf(len(res.UnlinkedLogins), "GitHub account") +
			" with organisation authority to a workforce identity, so the chain from a person to the " +
			"cloud cannot be drawn through them. Nothing in either system states the mapping, and " +
			"matching on name resemblance would produce a confident wrong path. Enable Okta SCIM " +
			"provisioning for GitHub, or GitHub SAML SSO (which publishes each member's external " +
			"identity), and the link becomes a fact rather than a guess."
	}
	return res
}

func acceptedSource(s string) bool {
	return s == LinkSourceOktaSCIM || s == LinkSourceGitHubSAML
}

func authority(c GitHubControl) string {
	switch {
	case c.Repo != "" && c.Admin:
		return "an admin"
	case c.Repo != "":
		return "a writer"
	case c.Admin:
		return "an owner"
	}
	return "a member"
}

// countOf renders "1 GitHub account" / "3 GitHub accounts".
func countOf(n int, noun string) string {
	s := strconv.Itoa(n) + " " + noun
	if n != 1 {
		s += "s"
	}
	return s
}
