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

// GitHub is the connector for GitHub orgs/repos — the tech-SMB wedge integration.
// Discover lists repos (→ repository assets); Watch turns a push webhook into a
// re-scan trigger; Apply opens a pull request with a verified fix. APIBase/OAuthBase
// are overridable so the whole thing is testable against an httptest server.
type GitHub struct {
	ClientID     string
	ClientSecret string
	APIBase      string // default https://api.github.com
	OAuthBase    string // default https://github.com
	HTTP         *http.Client
}

// NewGitHub builds a GitHub connector with production defaults.
func NewGitHub(clientID, clientSecret string) *GitHub {
	return &GitHub{
		ClientID: clientID, ClientSecret: clientSecret,
		APIBase: "https://api.github.com", OAuthBase: "https://github.com",
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (g *GitHub) Kind() string { return platform.ConnGitHub }

func (g *GitHub) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

func (g *GitHub) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":    {g.ClientID},
		"redirect_uri": {redirectURI},
		"scope":        {"repo read:org"},
		"state":        {state},
	}
	return strings.TrimRight(g.OAuthBase, "/") + "/login/oauth/authorize?" + q.Encode()
}

func (g *GitHub) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.OAuthBase, "/")+"/login/oauth/access_token", strings.NewReader(form.Encode()))
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
		return platform.Connection{}, fmt.Errorf("github: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("github: oauth exchange failed: %s", nz(tok.Error, "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller MUST seal it through the
	// secret vault and overwrite SecretRef before persisting (handleConnectCallback).
	return platform.Connection{
		Kind: platform.ConnGitHub, Status: platform.ConnActive,
		Scopes: []string{"repo", "read:org"}, CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// repo is the slice of the GitHub repo object we use.
type repo struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	Private  bool   `json:"private"`
	Archived bool   `json:"archived"`
}

func (g *GitHub) Discover(ctx context.Context, c platform.Connection, token string) ([]platform.Asset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(g.APIBase, "/")+"/user/repos?per_page=100&affiliation=owner,organization_member", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: list repos: HTTP %d", resp.StatusCode)
	}
	var repos []repo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&repos); err != nil {
		return nil, fmt.Errorf("github: decode repos: %w", err)
	}
	var assets []platform.Asset
	now := time.Now().UTC()
	for _, r := range repos {
		if r.Archived {
			continue // never scan an archived repo
		}
		assets = append(assets, platform.Asset{
			TenantID: c.TenantID, ConnectionID: c.ID,
			Type:         "repository",
			Target:       r.HTMLURL,
			Meta:         map[string]string{"full_name": r.FullName, "private": fmt.Sprintf("%t", r.Private)},
			DiscoveredAt: now,
		})
	}
	return assets, nil
}

// pushEvent is the slice of the GitHub push webhook we use.
type pushEvent struct {
	Ref        string `json:"ref"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

func (g *GitHub) Watch(_ context.Context, c platform.Connection, event []byte) ([]Trigger, error) {
	var ev pushEvent
	if err := json.Unmarshal(event, &ev); err != nil {
		return nil, fmt.Errorf("github: parse webhook: %w", err)
	}
	if ev.Repository.HTMLURL == "" {
		return nil, nil // not a repo event we act on
	}
	return []Trigger{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		AssetTarget: ev.Repository.HTMLURL, Kind: platform.TriggerPush,
	}}, nil
}

// pullRequestReq is the create-PR payload.
type pullRequestReq struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
}

func (g *GitHub) Apply(ctx context.Context, c platform.Connection, token string, a platform.Action) error {
	if a.Kind != platform.ActOpenPR {
		return fmt.Errorf("github: unsupported action kind %q", a.Kind)
	}
	full, _ := a.Payload["full_name"].(string)
	if full == "" {
		return fmt.Errorf("github: action missing full_name")
	}
	head := strFrom(a.Payload, "head")
	base := nz(strFrom(a.Payload, "base"), "main")

	// If the action carries patched file contents, COMMIT them to `head` first. Without this the PR
	// referenced a branch nothing had created, so an "AI fix" could never actually carry a diff — the
	// agent's patch had no path into the repository (see github_commit.go). WHERE THE HUMAN ACTUALLY IS, stated
	// precisely because this comment used to overstate it. A code-fix PR is tier 1 (remediate: "reversible
	// — review before merge"), which is BELOW platform.GateTier, so Desk.Submit AUTO-APPLIES it: nobody
	// approves this in our Inbox. The gate is the customer's OWN pull-request review, in their repo, under
	// their branch protection — a legitimate gate, and a different one from the desk. What is guaranteed
	// here is narrower than "a human approved it": the write lands on a FEATURE BRANCH and a pull request,
	// never on the default branch, and the kill-switch still stops it.
	if files := filesFrom(a.Payload); len(files) > 0 {
		if head == "" {
			return fmt.Errorf("github: a patch was supplied but the action has no head branch to commit it to")
		}
		msg := nz(strFrom(a.Payload, "commit_message"), nz(a.Title, "tsengine: security fix"))
		if err := g.CommitFiles(ctx, token, full, base, head, msg, files); err != nil {
			return err // surfaced, never a silent "fixed" (a 403 here = the App lacks contents: write)
		}
	}

	body := pullRequestReq{
		Title: nz(a.Title, "tsengine: verified security fix"),
		Head:  head,
		Base:  base,
		Body:  strFrom(a.Payload, "body"),
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.APIBase, "/")+"/repos/"+full+"/pulls", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github: open PR: HTTP %d", resp.StatusCode)
	}
	return nil
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
func strFrom(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// Configured reports whether this deployment supplied the OAuth credentials this
// connector needs. Without them the authorize URL would be built with an empty
// client_id and dead-end the customer on the provider's error page.
func (g *GitHub) Configured() bool { return g.ClientID != "" && g.ClientSecret != "" }
