package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Bitbucket is the connector for Bitbucket Cloud — the third tech-SCM integration alongside
// GitHub + GitLab (many SMBs, especially Atlassian shops, live here). Discover lists the
// workspaces' repositories (→ repository assets); Watch turns a repo:push webhook into a
// re-scan trigger; Apply opens a pull request with a verified fix. Mirrors connector.GitLab.
//
// Bitbucket splits its hosts: OAuth lives on bitbucket.org, the REST API on api.bitbucket.org.
// Both are overridable (OAuthBase + APIBase) so a test can point them at one fake server.
type Bitbucket struct {
	ClientID     string
	ClientSecret string
	OAuthBase    string // default https://bitbucket.org
	APIBase      string // default https://api.bitbucket.org/2.0
	HTTP         *http.Client
}

// NewBitbucket builds the connector for Bitbucket Cloud.
func NewBitbucket(clientID, clientSecret string) *Bitbucket {
	return &Bitbucket{
		ClientID: clientID, ClientSecret: clientSecret,
		OAuthBase: "https://bitbucket.org", APIBase: "https://api.bitbucket.org/2.0",
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (b *Bitbucket) Kind() string { return platform.ConnBitbucket }

func (b *Bitbucket) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return http.DefaultClient
}

func (b *Bitbucket) oauthBase() string { return strings.TrimRight(b.OAuthBase, "/") }
func (b *Bitbucket) apiBase() string   { return strings.TrimRight(b.APIBase, "/") }

// OAuthURL builds the consent URL. Bitbucket Cloud scopes are configured on the OAuth
// consumer (not passed here); we request read+write so Discover and the PR-opening Apply work.
func (b *Bitbucket) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {b.ClientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"state":         {state},
	}
	return b.oauthBase() + "/site/oauth2/authorize?" + q.Encode()
}

func (b *Bitbucket) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.oauthBase()+"/site/oauth2/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return platform.Connection{}, err
	}
	// Bitbucket authenticates the token request with HTTP Basic (consumer key:secret).
	req.SetBasicAuth(b.ClientID, b.ClientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client().Do(req)
	if err != nil {
		return platform.Connection{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return platform.Connection{}, fmt.Errorf("bitbucket: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("bitbucket: oauth exchange failed: %s", nz(nz(tok.ErrorDesc, tok.Error), "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it (see github.go).
	return platform.Connection{
		Kind: platform.ConnBitbucket, Status: platform.ConnActive,
		Scopes: []string{"repository", "pullrequest:write"}, CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// bbRepoPage is the slice of the Bitbucket repositories list-response we use (paginated).
type bbRepoPage struct {
	Values []struct {
		FullName  string `json:"full_name"`
		IsPrivate bool   `json:"is_private"`
		Links     struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	} `json:"values"`
	Next string `json:"next"` // absolute URL of the next page, or "" when done
}

func (b *Bitbucket) Discover(ctx context.Context, c platform.Connection, token string) ([]platform.Asset, error) {
	// role=member scopes to repos the user can access; pagelen=100 is Bitbucket's max. We follow
	// `next` (bounded) rather than silently capping at one page.
	next := b.apiBase() + "/repositories?role=member&pagelen=100"
	var assets []platform.Asset
	now := time.Now().UTC()
	for page := 0; next != "" && page < 50; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := b.client().Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("bitbucket: list repositories: HTTP %d", resp.StatusCode)
		}
		var pg bbRepoPage
		derr := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&pg)
		resp.Body.Close()
		if derr != nil {
			return nil, fmt.Errorf("bitbucket: decode repositories: %w", derr)
		}
		for _, r := range pg.Values {
			vis := "public"
			if r.IsPrivate {
				vis = "private"
			}
			target := r.Links.HTML.Href
			if target == "" {
				target = "https://bitbucket.org/" + r.FullName
			}
			assets = append(assets, platform.Asset{
				TenantID: c.TenantID, ConnectionID: c.ID,
				Type: "repository", Target: target,
				Meta:         map[string]string{"path": r.FullName, "visibility": vis},
				DiscoveredAt: now,
			})
		}
		next = pg.Next
	}
	return assets, nil
}

// bbPush is the slice of the Bitbucket repo:push webhook we use.
type bbPush struct {
	Push       *json.RawMessage `json:"push"` // presence distinguishes a push event
	Repository struct {
		FullName string `json:"full_name"`
		Links    struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	} `json:"repository"`
}

func (b *Bitbucket) Watch(_ context.Context, c platform.Connection, event []byte) ([]Trigger, error) {
	var h bbPush
	if err := json.Unmarshal(event, &h); err != nil {
		return nil, fmt.Errorf("bitbucket: parse webhook: %w", err)
	}
	if h.Push == nil { // not a repo:push payload
		return nil, nil
	}
	target := h.Repository.Links.HTML.Href
	if target == "" && h.Repository.FullName != "" {
		target = "https://bitbucket.org/" + h.Repository.FullName
	}
	if target == "" {
		return nil, nil
	}
	return []Trigger{{TenantID: c.TenantID, ConnectionID: c.ID, AssetTarget: target, Kind: platform.TriggerPush}}, nil
}

func (b *Bitbucket) Apply(ctx context.Context, c platform.Connection, token string, a platform.Action) error {
	if a.Kind != platform.ActOpenPR {
		return fmt.Errorf("bitbucket: unsupported action kind %q", a.Kind)
	}
	// Bitbucket addresses a repo by "{workspace}/{repo_slug}" — the full_name we stored in Meta.
	repo := strFrom(a.Payload, "path")
	if repo == "" {
		repo = strFrom(a.Payload, "repo")
	}
	if repo == "" {
		return fmt.Errorf("bitbucket: action missing repo path (workspace/repo_slug)")
	}
	pr := map[string]any{
		"title":       nz(a.Title, "tsengine: verified security fix"),
		"description": strFrom(a.Payload, "body"),
		"source":      map[string]any{"branch": map[string]any{"name": strFrom(a.Payload, "head")}},
		"destination": map[string]any{"branch": map[string]any{"name": nz(strFrom(a.Payload, "base"), "main")}},
	}
	raw, err := json.Marshal(pr)
	if err != nil {
		return err
	}
	endpoint := b.apiBase() + "/repositories/" + repo + "/pullrequests"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bitbucket: open PR: HTTP %d", resp.StatusCode)
	}
	return nil
}
