// Package identitylinks fetches the inputs the estate graph needs to draw the chain from a PERSON
// to the CODE they control: which workforce identity holds which GitHub account, and which GitHub
// account holds authority over which organisation or repository.
//
// THE GAP THIS CLOSES. `estateingest.GitHubIdentity` (the join) and `GitHubOIDC` (repository → cloud
// role) were built, tested, and had no non-test caller, because nothing in the tree FETCHED what
// they join over: Okta names a person by email, GitHub by login, and neither dataset volunteers the
// mapping. So the product's own wedge — identity → code → cloud — was declared broken by design, in
// prose, on every estate.
//
// TWO ASSERTED SOURCES, AND NOTHING ELSE. A link is accepted only when a system that KNOWS states it:
//
//   - GitHub SAML: the organisation's external identities (GraphQL `samlIdentityProvider.
//     externalIdentities`) pair each member's login with the nameId the IdP sent. Needs admin:org;
//     an org without SAML SSO has none, and both are reported as unread rather than as "no links".
//   - Okta SCIM: Okta's assignment of a person to the GitHub app records the GitHub-side id it
//     provisioned (`externalId`); GitHub's member list carries each login's numeric id. Two systems
//     stating the same number is a fact; a login that resembles an email is not, and is never used.
//
// Authority comes from GitHub itself: organisation owners (`/orgs/{org}/members?role=admin`) and
// per-repository direct collaborators with admin or push permission. Every control carries the
// endpoint that stated it.
//
// Every source that could not be read is NAMED in Unread with the reason. An empty link set and an
// unreadable one must never render alike, because the estate page turns the first into "nobody at
// this company controls code" and the second into a broken chain it can tell the reader how to fix.
package identitylinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

const (
	SourceOktaSCIM   = "okta_scim"
	SourceGitHubSAML = "github_saml"
)

// Options are the deployment-level knobs; Inputs are one tenant's.
type Options struct {
	GitHubAPIBase string // default https://api.github.com
	OktaOrgURL    string // the Okta org base; "" → Okta is not read
	HTTP          *http.Client
	// MaxRepos bounds the collaborator reads per pass; the rest are named as unread.
	MaxRepos int
}

type Inputs struct {
	TenantID    string
	GitHubOrg   string
	GitHubToken string
	Repos       []string // "owner/name", the tenant's connected repositories
	OktaToken   string   // "" → no Okta connection
	Now         time.Time
}

func (o Options) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (o Options) ghBase() string {
	if o.GitHubAPIBase != "" {
		return strings.TrimRight(o.GitHubAPIBase, "/")
	}
	return "https://api.github.com"
}

// Fetch reads every source the inputs make available and returns the set with its unread notes.
func Fetch(ctx context.Context, opts Options, in Inputs) platform.IdentityLinkSet {
	set := platform.IdentityLinkSet{TenantID: in.TenantID, Links: []platform.IdentityLink{}, Controls: []platform.GitHubControl{},
		FetchedAt: in.Now.UTC(), Unread: map[string]string{}}
	if in.GitHubOrg == "" || in.GitHubToken == "" {
		set.Unread["github"] = "no GitHub organisation connection — nothing states who controls code"
		if in.OktaToken != "" {
			set.Unread[SourceOktaSCIM] = "Okta's GitHub assignment can only be joined to GitHub's own member ids, and GitHub is not connected"
		}
		return set
	}

	// 1. GitHub members with their numeric ids (the join key for Okta), and the org owners.
	members, err := ghMembers(ctx, opts, in.GitHubOrg, in.GitHubToken, "")
	if err != nil {
		set.Unread["github_members"] = "could not list organisation members: " + err.Error()
	}
	idByLogin := map[string]int64{}
	loginByID := map[int64]string{}
	for _, m := range members {
		idByLogin[strings.ToLower(m.Login)] = m.ID
		loginByID[m.ID] = m.Login
	}
	if owners, err := ghMembers(ctx, opts, in.GitHubOrg, in.GitHubToken, "admin"); err != nil {
		set.Unread["github_owners"] = "could not list organisation owners: " + err.Error()
	} else {
		for _, o := range owners {
			set.Controls = append(set.Controls, platform.GitHubControl{Login: o.Login, Org: in.GitHubOrg, Admin: true,
				Evidence: []string{"GET /orgs/" + in.GitHubOrg + "/members?role=admin"}})
		}
	}

	// 2. Per-repository direct collaborators with admin or push.
	max := opts.MaxRepos
	if max <= 0 {
		max = 100
	}
	for i, full := range in.Repos {
		if i >= max {
			set.Unread["collaborators"] = fmt.Sprintf("%d of %d repositories read this pass; the rest wait for the next", max, len(in.Repos))
			break
		}
		cols, err := ghCollaborators(ctx, opts, full, in.GitHubToken)
		if err != nil {
			set.Unread["collaborators:"+full] = err.Error()
			continue
		}
		for _, c := range cols {
			if !c.Permissions.Admin && !c.Permissions.Push {
				continue
			}
			owner, repo, _ := strings.Cut(full, "/")
			set.Controls = append(set.Controls, platform.GitHubControl{Login: c.Login, Org: owner, Repo: repo, Admin: c.Permissions.Admin,
				Evidence: []string{"GET /repos/" + full + "/collaborators?affiliation=direct (permissions." + permName(c.Permissions.Admin) + ")"}})
		}
	}

	// 3. GitHub SAML external identities: login ↔ nameId, asserted by GitHub.
	saml, samlErr := ghSAMLIdentities(ctx, opts, in.GitHubOrg, in.GitHubToken)
	switch {
	case samlErr != nil:
		set.Unread[SourceGitHubSAML] = samlErr.Error()
	default:
		for _, s := range saml {
			if s.login == "" || !strings.Contains(s.nameID, "@") {
				continue
			}
			set.Links = append(set.Links, platform.IdentityLink{Email: strings.ToLower(s.nameID), Login: s.login, Source: SourceGitHubSAML})
		}
	}

	// 4. Okta's GitHub app assignments, joined on GitHub's numeric user id.
	if in.OktaToken == "" || opts.OktaOrgURL == "" {
		set.Unread[SourceOktaSCIM] = "no Okta connection"
	} else if err := oktaAssignments(ctx, opts, in.OktaToken, loginByID, &set); err != nil {
		set.Unread[SourceOktaSCIM] = err.Error()
	}
	return set
}

func permName(admin bool) string {
	if admin {
		return "admin"
	}
	return "push"
}

// --- GitHub REST ---

type ghMember struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

func ghMembers(ctx context.Context, opts Options, org, token, role string) ([]ghMember, error) {
	u := opts.ghBase() + "/orgs/" + url.PathEscape(org) + "/members?per_page=100"
	if role != "" {
		u += "&role=" + role
	}
	var out []ghMember
	err := ghPages(ctx, opts, u, token, func(body []byte) error {
		var page []ghMember
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("members page is not a member list: %w", err)
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

type ghCollaborator struct {
	Login       string `json:"login"`
	Permissions struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
	} `json:"permissions"`
}

func ghCollaborators(ctx context.Context, opts Options, full, token string) ([]ghCollaborator, error) {
	u := opts.ghBase() + "/repos/" + full + "/collaborators?affiliation=direct&per_page=100"
	var out []ghCollaborator
	err := ghPages(ctx, opts, u, token, func(body []byte) error {
		var page []ghCollaborator
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("collaborators page is not a list: %w", err)
		}
		out = append(out, page...)
		return nil
	})
	return out, err
}

// ghPages walks a Link-header paged REST listing.
func ghPages(ctx context.Context, opts Options, next, token string, fn func([]byte) error) error {
	for p := 0; next != "" && p < 20; p++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		res, err := opts.client().Do(req)
		if err != nil {
			return err
		}
		body, rerr := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if rerr != nil {
			return rerr
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d from %s", res.StatusCode, next)
		}
		if err := fn(body); err != nil {
			return err
		}
		next = nextLink(res.Header.Values("Link"))
	}
	return nil
}

func nextLink(links []string) string {
	for _, l := range links {
		for _, part := range strings.Split(l, ",") {
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			s, e := strings.Index(part, "<"), strings.Index(part, ">")
			if s >= 0 && e > s {
				return part[s+1 : e]
			}
		}
	}
	return ""
}

// --- GitHub GraphQL: SAML external identities ---

type samlIdentity struct{ login, nameID string }

func ghSAMLIdentities(ctx context.Context, opts Options, org, token string) ([]samlIdentity, error) {
	var out []samlIdentity
	cursor := ""
	for p := 0; p < 20; p++ {
		q := map[string]any{
			"query":     `query($org:String!,$after:String){ organization(login:$org){ samlIdentityProvider{ externalIdentities(first:100, after:$after){ pageInfo{ hasNextPage endCursor } nodes{ user{ login } samlIdentity{ nameId } } } } } }`,
			"variables": map[string]any{"org": org, "after": nilIfEmpty(cursor)},
		}
		b, _ := json.Marshal(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.ghBase()+"/graphql", bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := opts.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, rerr := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		res.Body.Close()
		if rerr != nil {
			return nil, rerr
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GraphQL HTTP %d — reading SAML identities needs the admin:org scope on the GitHub connection", res.StatusCode)
		}
		var resp struct {
			Data struct {
				Organization *struct {
					SAML *struct {
						Ext struct {
							PageInfo struct {
								HasNext bool   `json:"hasNextPage"`
								End     string `json:"endCursor"`
							} `json:"pageInfo"`
							Nodes []struct {
								User *struct {
									Login string `json:"login"`
								} `json:"user"`
								SAML *struct {
									NameID string `json:"nameId"`
								} `json:"samlIdentity"`
							} `json:"nodes"`
						} `json:"externalIdentities"`
					} `json:"samlIdentityProvider"`
				} `json:"organization"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("GraphQL response is not JSON: %w", err)
		}
		if len(resp.Errors) > 0 {
			return nil, fmt.Errorf("GraphQL: %s (reading SAML identities needs the admin:org scope)", resp.Errors[0].Message)
		}
		if resp.Data.Organization == nil || resp.Data.Organization.SAML == nil {
			return nil, fmt.Errorf("the organisation has no SAML identity provider configured, so GitHub publishes no person↔login mapping — enable SAML SSO, or provision GitHub from Okta")
		}
		for _, n := range resp.Data.Organization.SAML.Ext.Nodes {
			if n.User == nil || n.SAML == nil {
				continue // an identity with no linked user is a pending invite, not a mapping
			}
			out = append(out, samlIdentity{login: n.User.Login, nameID: n.SAML.NameID})
		}
		if !resp.Data.Organization.SAML.Ext.PageInfo.HasNext {
			break
		}
		cursor = resp.Data.Organization.SAML.Ext.PageInfo.End
	}
	return out, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// --- Okta: the GitHub app's assignments, joined on GitHub's numeric id ---

func oktaAssignments(ctx context.Context, opts Options, token string, loginByID map[int64]string, set *platform.IdentityLinkSet) error {
	base := strings.TrimRight(opts.OktaOrgURL, "/")
	var apps []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Label  string `json:"label"`
		Status string `json:"status"`
	}
	if err := oktaGet(ctx, opts, token, base+"/api/v1/apps?limit=200", &apps); err != nil {
		return fmt.Errorf("could not list Okta apps: %w", err)
	}
	var github []string
	for _, a := range apps {
		n, l := strings.ToLower(a.Name), strings.ToLower(a.Label)
		if a.Status == "ACTIVE" && (strings.HasPrefix(n, "github") || strings.Contains(l, "github")) {
			github = append(github, a.ID)
		}
	}
	if len(github) == 0 {
		return fmt.Errorf("no GitHub app is assigned in Okta, so Okta asserts no person↔GitHub mapping")
	}
	if len(loginByID) == 0 {
		return fmt.Errorf("GitHub's member ids could not be read, so Okta's assignments have nothing to join to")
	}
	matched := 0
	for _, appID := range github {
		var users []struct {
			ID          string `json:"id"`
			ExternalID  string `json:"externalId"`
			Credentials struct {
				UserName string `json:"userName"`
			} `json:"credentials"`
			Profile struct {
				Email string `json:"email"`
			} `json:"profile"`
		}
		if err := oktaGet(ctx, opts, token, base+"/api/v1/apps/"+appID+"/users?limit=200", &users); err != nil {
			return fmt.Errorf("could not list the GitHub app's assignments: %w", err)
		}
		for _, u := range users {
			id, perr := strconv.ParseInt(strings.TrimSpace(u.ExternalID), 10, 64)
			if perr != nil {
				continue // not provisioned to GitHub yet, or GitHub's id not recorded — nothing to join
			}
			login, ok := loginByID[id]
			if !ok {
				continue
			}
			email := strings.ToLower(u.Profile.Email)
			if email == "" && strings.Contains(u.Credentials.UserName, "@") {
				email = strings.ToLower(u.Credentials.UserName)
			}
			if email == "" {
				continue
			}
			set.Links = append(set.Links, platform.IdentityLink{Email: email, Login: login, Source: SourceOktaSCIM})
			matched++
		}
	}
	if matched == 0 {
		return fmt.Errorf("Okta's GitHub app records no provisioned GitHub ids that match an organisation member — SCIM provisioning may not be enabled")
	}
	return nil
}

func oktaGet(ctx context.Context, opts Options, token, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	res, err := opts.client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if rerr != nil {
		return rerr
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("response is not the expected list: %w", err)
	}
	return nil
}
