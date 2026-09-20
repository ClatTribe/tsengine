package platformapi

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector/awsinventory"
	"github.com/ClatTribe/tsengine/internal/estateingest"
	"github.com/ClatTribe/tsengine/internal/ghoidc"
)

// githubTrustsFrom derives the repository → role transitions an account's trust policies state, for
// the cloud snapshot to keep. The built inventory drops the raw trust documents, so without this the
// estate graph could draw code → cloud only in the request that posted the snapshot and never on
// the page a human reads days later. Grounded (§10): a wildcard subject names no single repository
// and yields no edge (estateingest.TrustsFrom's rule); a role that trusts no GitHub provider yields
// nothing.
func githubTrustsFrom(raw awsinventory.RawAWS) []cloudsnap.GitHubTrust {
	var out []cloudsnap.GitHubTrust
	for _, r := range raw.Roles {
		if strings.TrimSpace(r.TrustPolicyJSON) == "" {
			continue
		}
		an := ghoidc.Analyze([]byte(r.TrustPolicyJSON))
		for _, t := range estateingest.TrustsFrom(an, r.ARN, r.Name, r.Admin, []string{"trust-policy:" + r.ARN}) {
			if t.Repository == "" {
				continue // a role-only entry is a node the cloud graph already has, not a transition
			}
			out = append(out, cloudsnap.GitHubTrust{Repository: t.Repository, RoleARN: t.RoleARN, RoleName: t.RoleName,
				Privileged: t.Privileged, Evidence: t.Evidence, Why: t.Why})
		}
	}
	return out
}

// oidcTrusts converts stored snapshot trusts back into the estate converter's input.
func oidcTrusts(ts []cloudsnap.GitHubTrust) []estateingest.GitHubOIDCTrust {
	out := make([]estateingest.GitHubOIDCTrust, 0, len(ts))
	for _, t := range ts {
		out = append(out, estateingest.GitHubOIDCTrust{Repository: t.Repository, RoleARN: t.RoleARN, RoleName: t.RoleName,
			Privileged: t.Privileged, Evidence: t.Evidence, Why: t.Why})
	}
	return out
}
