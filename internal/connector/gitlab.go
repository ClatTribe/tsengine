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

// GitLab is the connector for GitLab (gitlab.com or self-managed) — the second tech-SCM
// integration alongside GitHub. Discover lists projects (→ repository assets); Watch
// turns a Push Hook into a re-scan trigger; Apply opens a merge request with a verified
// fix. Mirrors connector.GitHub. BaseURL is overridable for self-managed + tests.
type GitLab struct {
	ClientID     string
	ClientSecret string
	BaseURL      string // default https://gitlab.com
	HTTP         *http.Client
}

// NewGitLab builds the connector for gitlab.com.
func NewGitLab(clientID, clientSecret string) *GitLab {
	return &GitLab{ClientID: clientID, ClientSecret: clientSecret, BaseURL: "https://gitlab.com", HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (g *GitLab) Kind() string { return platform.ConnGitLab }

func (g *GitLab) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

func (g *GitLab) base() string { return strings.TrimRight(g.BaseURL, "/") }

func (g *GitLab) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {g.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"read_api api"},
		"state":         {state},
	}
	return g.base() + "/oauth/authorize?" + q.Encode()
}

func (g *GitLab) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base()+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return platform.Connection{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(req)
	if err != nil {
		return platform.Connection{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return platform.Connection{}, fmt.Errorf("gitlab: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("gitlab: oauth exchange failed: %s", nz(tok.Error, "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it (see github.go).
	return platform.Connection{
		Kind: platform.ConnGitLab, Status: platform.ConnActive,
		Scopes: []string{"read_api", "api"}, CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// project is the slice of the GitLab project object we use.
type project struct {
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	Visibility        string `json:"visibility"`
	Archived          bool   `json:"archived"`
}

func (g *GitLab) Discover(ctx context.Context, c platform.Connection, token string) ([]platform.Asset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		g.base()+"/api/v4/projects?membership=true&per_page=100&simple=true", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab: list projects: HTTP %d", resp.StatusCode)
	}
	var projects []project
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&projects); err != nil {
		return nil, fmt.Errorf("gitlab: decode projects: %w", err)
	}
	var assets []platform.Asset
	now := time.Now().UTC()
	for _, p := range projects {
		if p.Archived {
			continue
		}
		assets = append(assets, platform.Asset{
			TenantID: c.TenantID, ConnectionID: c.ID,
			Type: "repository", Target: p.WebURL,
			Meta:         map[string]string{"path": p.PathWithNamespace, "visibility": p.Visibility},
			DiscoveredAt: now,
		})
	}
	return assets, nil
}

// pushHook is the slice of the GitLab Push Hook we use.
type pushHook struct {
	ObjectKind string `json:"object_kind"`
	Project    struct {
		WebURL string `json:"web_url"`
	} `json:"project"`
}

func (g *GitLab) Watch(_ context.Context, c platform.Connection, event []byte) ([]Trigger, error) {
	var h pushHook
	if err := json.Unmarshal(event, &h); err != nil {
		return nil, fmt.Errorf("gitlab: parse webhook: %w", err)
	}
	if h.ObjectKind != "push" || h.Project.WebURL == "" {
		return nil, nil
	}
	return []Trigger{{TenantID: c.TenantID, ConnectionID: c.ID, AssetTarget: h.Project.WebURL, Kind: platform.TriggerPush}}, nil
}

func (g *GitLab) Apply(ctx context.Context, c platform.Connection, token string, a platform.Action) error {
	if a.Kind != platform.ActOpenPR {
		return fmt.Errorf("gitlab: unsupported action kind %q", a.Kind)
	}
	pid, _ := a.Payload["project_id"].(string)
	if pid == "" {
		pid, _ = a.Payload["path"].(string) // URL-encode the path-with-namespace form
	}
	if pid == "" {
		return fmt.Errorf("gitlab: action missing project_id/path")
	}
	body := url.Values{
		"source_branch": {strFrom(a.Payload, "head")},
		"target_branch": {nz(strFrom(a.Payload, "base"), "main")},
		"title":         {nz(a.Title, "tsengine: verified security fix")},
		"description":   {strFrom(a.Payload, "body")},
	}
	endpoint := g.base() + "/api/v4/projects/" + url.PathEscape(pid) + "/merge_requests"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gitlab: open MR: HTTP %d", resp.StatusCode)
	}
	return nil
}
