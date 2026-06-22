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

// AzureDevOps is the connector for Azure DevOps (Repos) — the fourth tech-SCM integration, for the
// many Microsoft-shop SMBs on Azure DevOps rather than GitHub/GitLab/Bitbucket. Discover lists the
// org's Git repositories (→ repository assets); Watch turns a git.push service hook into a re-scan
// trigger; Apply opens a pull request with a verified fix. Mirrors connector.Bitbucket.
//
// Azure DevOps is ORG-scoped (dev.azure.com/{org}) and the org isn't carried in the OAuth flow, so
// it's configured (Org). OAuth uses the legacy vssps jwt-bearer grant; both hosts (OAuth on
// app.vssps.visualstudio.com, REST on dev.azure.com) are overridable for tests.
type AzureDevOps struct {
	ClientID     string // the registered app's "App ID"
	ClientSecret string // the app's "Client Secret" (used as the client_assertion)
	Org          string // the Azure DevOps organization (dev.azure.com/{Org})
	OAuthBase    string // default https://app.vssps.visualstudio.com
	APIBase      string // default https://dev.azure.com
	HTTP         *http.Client
}

// NewAzureDevOps builds the connector for an organization.
func NewAzureDevOps(clientID, clientSecret, org string) *AzureDevOps {
	return &AzureDevOps{
		ClientID: clientID, ClientSecret: clientSecret, Org: org,
		OAuthBase: "https://app.vssps.visualstudio.com", APIBase: "https://dev.azure.com",
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (a *AzureDevOps) Kind() string { return platform.ConnAzureDevOps }

func (a *AzureDevOps) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return http.DefaultClient
}

func (a *AzureDevOps) oauthBase() string { return strings.TrimRight(a.OAuthBase, "/") }
func (a *AzureDevOps) apiBase() string   { return strings.TrimRight(a.APIBase, "/") }

// OAuthURL builds the consent URL (response_type=Assertion is Azure DevOps's OAuth flavor).
func (a *AzureDevOps) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {a.ClientID},
		"response_type": {"Assertion"},
		"state":         {state},
		"scope":         {"vso.code vso.code_write"},
		"redirect_uri":  {redirectURI},
	}
	return a.oauthBase() + "/oauth2/authorize?" + q.Encode()
}

func (a *AzureDevOps) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {a.ClientSecret},
		"grant_type":            {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":             {code},
		"redirect_uri":          {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oauthBase()+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return platform.Connection{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client().Do(req)
	if err != nil {
		return platform.Connection{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"Error"`
		ErrorDesc   string `json:"ErrorDescription"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return platform.Connection{}, fmt.Errorf("azuredevops: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("azuredevops: oauth exchange failed: %s", nz(nz(tok.ErrorDesc, tok.Error), "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it (see github.go). Account
	// records the org so the API base is reconstructable from the stored connection.
	return platform.Connection{
		Kind: platform.ConnAzureDevOps, Status: platform.ConnActive, Account: a.Org,
		Scopes: []string{"vso.code", "vso.code_write"}, CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// adoRepoList is the slice of the Azure DevOps repositories response we use. The REST list returns
// all repos in one call (no pagination cursor), so Discover is a single request.
type adoRepoList struct {
	Value []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		WebURL     string `json:"webUrl"`
		IsDisabled bool   `json:"isDisabled"`
		Project    struct {
			Name string `json:"name"`
		} `json:"project"`
	} `json:"value"`
}

func (a *AzureDevOps) Discover(ctx context.Context, c platform.Connection, token string) ([]platform.Asset, error) {
	org := a.org(c)
	if org == "" {
		return nil, fmt.Errorf("azuredevops: organization not configured")
	}
	endpoint := a.apiBase() + "/" + url.PathEscape(org) + "/_apis/git/repositories?api-version=7.0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azuredevops: list repositories: HTTP %d", resp.StatusCode)
	}
	var list adoRepoList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("azuredevops: decode repositories: %w", err)
	}
	var assets []platform.Asset
	now := time.Now().UTC()
	for _, r := range list.Value {
		if r.IsDisabled {
			continue
		}
		target := r.WebURL
		if target == "" {
			target = a.apiBase() + "/" + org + "/" + r.Project.Name + "/_git/" + r.Name
		}
		assets = append(assets, platform.Asset{
			TenantID: c.TenantID, ConnectionID: c.ID,
			Type: "repository", Target: target,
			Meta:         map[string]string{"path": org + "/" + r.Project.Name + "/" + r.Name, "project": r.Project.Name, "repo_id": r.ID},
			DiscoveredAt: now,
		})
	}
	return assets, nil
}

// adoPush is the slice of the Azure DevOps git.push service-hook we use.
type adoPush struct {
	EventType string `json:"eventType"`
	Resource  struct {
		Repository struct {
			RemoteURL string `json:"remoteUrl"`
			Name      string `json:"name"`
			Project   struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"repository"`
	} `json:"resource"`
}

func (a *AzureDevOps) Watch(_ context.Context, c platform.Connection, event []byte) ([]Trigger, error) {
	var h adoPush
	if err := json.Unmarshal(event, &h); err != nil {
		return nil, fmt.Errorf("azuredevops: parse webhook: %w", err)
	}
	if h.EventType != "git.push" {
		return nil, nil
	}
	target := h.Resource.Repository.RemoteURL
	if target == "" {
		return nil, nil
	}
	return []Trigger{{TenantID: c.TenantID, ConnectionID: c.ID, AssetTarget: target, Kind: platform.TriggerPush}}, nil
}

func (a *AzureDevOps) Apply(ctx context.Context, c platform.Connection, token string, act platform.Action) error {
	if act.Kind != platform.ActOpenPR {
		return fmt.Errorf("azuredevops: unsupported action kind %q", act.Kind)
	}
	org := a.org(c)
	project := strFrom(act.Payload, "project")
	repoID := nz(strFrom(act.Payload, "repo_id"), strFrom(act.Payload, "repo"))
	if org == "" || project == "" || repoID == "" {
		return fmt.Errorf("azuredevops: action missing org/project/repo_id")
	}
	pr := map[string]any{
		"sourceRefName": "refs/heads/" + strFrom(act.Payload, "head"),
		"targetRefName": "refs/heads/" + nz(strFrom(act.Payload, "base"), "main"),
		"title":         nz(act.Title, "tsengine: verified security fix"),
		"description":   strFrom(act.Payload, "body"),
	}
	raw, err := json.Marshal(pr)
	if err != nil {
		return err
	}
	endpoint := a.apiBase() + "/" + url.PathEscape(org) + "/" + url.PathEscape(project) +
		"/_apis/git/repositories/" + url.PathEscape(repoID) + "/pullrequests?api-version=7.0"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("azuredevops: open PR: HTTP %d", resp.StatusCode)
	}
	return nil
}

// org resolves the organization: the connector's configured Org, else the connection's Account
// (recorded at Exchange) — so a stored connection stays usable even if the env default changes.
func (a *AzureDevOps) org(c platform.Connection) string {
	if a.Org != "" {
		return a.Org
	}
	return c.Account
}
