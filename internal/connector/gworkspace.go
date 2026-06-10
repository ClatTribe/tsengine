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

// GWorkspace is the OAuth onboarding connector for Google Workspace — it lets a
// non-tech tenant connect their directory so the operate posture engine can assess it.
// Discover yields a single "workspace" asset (the operate layer's input); the live
// directory fetch itself lives in internal/operate (GWorkspace.Fetch). Watch is a
// no-op (posture is scheduled, not webhook-driven); Apply is unsupported for now
// (identity remediation is future work). Bases are overridable for tests.
type GWorkspace struct {
	ClientID     string
	ClientSecret string
	OAuthBase    string // default https://accounts.google.com
	TokenBase    string // default https://oauth2.googleapis.com
	HTTP         *http.Client
}

// NewGWorkspace builds the connector with production defaults.
func NewGWorkspace(clientID, clientSecret string) *GWorkspace {
	return &GWorkspace{
		ClientID: clientID, ClientSecret: clientSecret,
		OAuthBase: "https://accounts.google.com", TokenBase: "https://oauth2.googleapis.com",
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (g *GWorkspace) Kind() string { return platform.ConnGWorkspace }

func (g *GWorkspace) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

const gworkspaceScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"

func (g *GWorkspace) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {g.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {gworkspaceScope},
		"access_type":   {"offline"},
		"state":         {state},
	}
	return strings.TrimRight(g.OAuthBase, "/") + "/o/oauth2/v2/auth?" + q.Encode()
}

func (g *GWorkspace) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.TokenBase, "/")+"/token", strings.NewReader(form.Encode()))
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
		return platform.Connection{}, fmt.Errorf("gworkspace: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("gworkspace: oauth exchange failed: %s", nz(tok.Error, "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it (see github.go).
	return platform.Connection{
		Kind: platform.ConnGWorkspace, Status: platform.ConnActive,
		Scopes: []string{gworkspaceScope}, CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// Discover returns the single workspace asset the operate engine assesses.
func (g *GWorkspace) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type:         "workspace",
		Target:       nz(c.Account, "google-workspace"),
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: identity/email posture is scheduled, not webhook-driven.
func (g *GWorkspace) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply is unsupported today (autonomous identity remediation is future work).
func (g *GWorkspace) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return fmt.Errorf("gworkspace: apply not supported yet")
}
