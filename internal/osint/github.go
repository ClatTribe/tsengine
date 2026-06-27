package osint

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
)

// GitHub code-search collector — finds the org's secrets leaked in THIRD-PARTY public repositories: a former
// employee's personal repo, a contractor's project, a config dumped into a gist-as-repo. This is the
// attacker's-eye external angle (what GitGuardian / SpiderFoot do), DISTINCT from the repository asset's
// gitleaks/trufflehog (which scan the org's OWN repos). The DETECTION already exists — osint::leaked-secret
// (LeakedSecret); this file is the live COLLECTOR that produces those entries.
//
// Unlike crt.sh (keyless), GitHub's code-search API REQUIRES authentication, so the live fetch is the
// credential-gated half: the caller injects a GitHub-token-authed Fetcher (the package stays auth-free, like
// CollectCT). The query builder + response parser here are pure + unit-testable; only the network call is gated.

// secretDork pairs a secret Kind with the literal marker GitHub code-search matches near the org identifier.
// Each is a high-signal token prefix that an attacker would grep for; tying it to the org's own domain keeps
// the hit grounded (a real org identifier next to a real secret-shaped token), not a generic noise match.
var secretDorks = []secretDork{
	{"AWS access key", "AKIA"},
	{"GitHub token", "ghp_"},
	{"Slack token", "xoxb-"},
	{"Google API key", "AIza"},
	{"Stripe live key", "sk_live_"},
	{"private key", `"BEGIN PRIVATE KEY"`},
}

type secretDork struct{ Kind, Marker string }

// GitHubCodeSearchURL builds the authenticated code-search query for an org identifier near a secret marker.
func GitHubCodeSearchURL(orgIdentifier, marker string) string {
	q := `"` + strings.TrimSpace(orgIdentifier) + `" ` + marker
	return "https://api.github.com/search/code?per_page=20&q=" + url.QueryEscape(q)
}

// ghCodeResp is the minimal GitHub /search/code response shape.
type ghCodeResp struct {
	Items []struct {
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"` // "owner/repo"
		} `json:"repository"`
	} `json:"items"`
}

// ParseGitHubCodeSearch turns one code-search response into LeakedSecret entries of the given Kind. Pure +
// testable. ownOrgs (lowercased GitHub owner logins the tenant controls) are SKIPPED — a hit in the org's own
// repo is the repository asset's job, not external exposure (the §10-grounded "someone ELSE's repo" nuance).
func ParseGitHubCodeSearch(kind string, body []byte, ownOrgs map[string]bool) []LeakedSecret {
	var r ghCodeResp
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	var out []LeakedSecret
	for _, it := range r.Items {
		loc := strings.TrimSpace(it.HTMLURL)
		if loc == "" {
			continue
		}
		if owner := ownerOf(it.Repository.FullName); owner != "" && ownOrgs[owner] {
			continue // the org's own repo — out of scope for external-exposure OSINT
		}
		out = append(out, LeakedSecret{Kind: kind, Location: loc, Source: "github-search"})
	}
	return out
}

func ownerOf(fullName string) string {
	if i := strings.IndexByte(fullName, '/'); i > 0 {
		return strings.ToLower(fullName[:i])
	}
	return ""
}

// CollectGitHubLeaks runs the secret-dork queries over the org's domains and returns a Snapshot of LeakedSecret
// entries (deduped by location) ready for Assess. The injected Fetcher must carry a GitHub token (the gated
// half); a per-query failure is best-effort and never aborts the collection. ownOrgs are excluded as above.
func CollectGitHubLeaks(ctx context.Context, org string, domains []string, ownOrgs map[string]bool, fetch Fetcher) Snapshot {
	snap := Snapshot{Org: org, Domains: domains}
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		for _, dork := range secretDorks {
			body, err := fetch(ctx, GitHubCodeSearchURL(d, dork.Marker))
			if err != nil {
				continue // best-effort per query
			}
			for _, ls := range ParseGitHubCodeSearch(dork.Kind, body, ownOrgs) {
				if seen[ls.Location] {
					continue // one repo file can match several dorks — count it once
				}
				seen[ls.Location] = true
				snap.LeakedSecrets = append(snap.LeakedSecrets, ls)
			}
		}
	}
	return snap
}
