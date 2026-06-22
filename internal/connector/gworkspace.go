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
	APIBase      string // Admin SDK base; default https://admin.googleapis.com (overridable for tests)
	HTTP         *http.Client
}

// NewGWorkspace builds the connector with production defaults.
func NewGWorkspace(clientID, clientSecret string) *GWorkspace {
	return &GWorkspace{
		ClientID: clientID, ClientSecret: clientSecret,
		OAuthBase: "https://accounts.google.com", TokenBase: "https://oauth2.googleapis.com",
		APIBase: "https://admin.googleapis.com",
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (g *GWorkspace) apiBase() string {
	if g.APIBase == "" {
		return "https://admin.googleapis.com"
	}
	return strings.TrimRight(g.APIBase, "/")
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
		Meta:         map[string]string{"provider": platform.ConnGWorkspace}, // gates which identity remediations have a live write path
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: identity/email posture is scheduled, not webhook-driven.
func (g *GWorkspace) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply is unsupported today (autonomous identity remediation is future work).
// Apply executes a gated identity remediation against Google Workspace. Reached only after the
// HITL gate (§18.2 inv. 3); the connector never writes on its own. Today: account_suspend (the fix
// for a stale/over-privileged account). It needs the admin.directory.user WRITE scope — the
// onboarding scope is read-only by design, so a real suspend requires an admin to grant the write
// scope; until then Google returns 403 and Apply surfaces it honestly (never falsely "done").
func (g *GWorkspace) Apply(ctx context.Context, _ platform.Connection, token string, a platform.Action) error {
	rt, _ := a.Payload["remediation_type"].(string)
	target := strFrom(a.Payload, "target")
	switch rt {
	case "account_suspend":
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("gworkspace apply: action %s has no target user", a.ID)
		}
		return g.suspendUser(ctx, token, target)
	default:
		return fmt.Errorf("gworkspace apply: remediation_type %q has no live write path yet (target %s)", rt, target)
	}
}

// suspendUser sets suspended=true on a Workspace user (Admin SDK Directory API). userKey accepts
// the user's primary email directly.
func (g *GWorkspace) suspendUser(ctx context.Context, token, userKey string) error {
	endpoint := g.apiBase() + "/admin/directory/v1/users/" + url.PathEscape(userKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(`{"suspended":true}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gworkspace suspend %s: %w", userKey, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("gworkspace suspend %s: HTTP %d: %s (needs the admin.directory.user write scope)", userKey, resp.StatusCode, body)
	}
	return nil
}
