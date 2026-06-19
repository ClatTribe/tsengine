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

// M365 is the OAuth onboarding connector for Microsoft 365 / Entra ID — it lets a
// non-tech tenant connect their directory so the operate posture engine can assess it
// via Microsoft Graph. Mirrors connector.GWorkspace: Discover yields one "workspace"
// asset; Watch is a no-op (posture is scheduled); Apply is unsupported for now. Tenant
// defaults to "common"; Bases are overridable for tests.
type M365 struct {
	ClientID     string
	ClientSecret string
	Tenant       string // Entra tenant id or "common"
	OAuthBase    string // default https://login.microsoftonline.com
	HTTP         *http.Client
}

// NewM365 builds the connector with production defaults.
func NewM365(clientID, clientSecret string) *M365 {
	return &M365{
		ClientID: clientID, ClientSecret: clientSecret, Tenant: "common",
		OAuthBase: "https://login.microsoftonline.com",
		HTTP:      &http.Client{Timeout: 20 * time.Second},
	}
}

func (m *M365) Kind() string { return platform.ConnM365 }

func (m *M365) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return http.DefaultClient
}

func (m *M365) tenant() string {
	if m.Tenant == "" {
		return "common"
	}
	return m.Tenant
}

// graphScope: directory read for users + the auth-methods registration report.
const graphScope = "https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/AuditLog.Read.All offline_access"

func (m *M365) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {m.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {graphScope},
		"state":         {state},
	}
	return strings.TrimRight(m.OAuthBase, "/") + "/" + m.tenant() + "/oauth2/v2.0/authorize?" + q.Encode()
}

func (m *M365) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_id":     {m.ClientID},
		"client_secret": {m.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
		"scope":         {graphScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(m.OAuthBase, "/")+"/"+m.tenant()+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return platform.Connection{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client().Do(req)
	if err != nil {
		return platform.Connection{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return platform.Connection{}, fmt.Errorf("m365: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("m365: oauth exchange failed: %s", nz(tok.Error, "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it (see github.go).
	return platform.Connection{
		Kind: platform.ConnM365, Status: platform.ConnActive,
		Scopes: strings.Fields(graphScope), CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// Discover returns the single workspace asset the operate engine assesses.
func (m *M365) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type: "workspace", Target: nz(c.Account, "m365"),
		Meta:         map[string]string{"provider": platform.ConnM365}, // gates which identity remediations have a live write path
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: identity/email posture is scheduled, not webhook-driven.
func (m *M365) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply is unsupported today (autonomous identity remediation is future work).
func (m *M365) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return fmt.Errorf("m365: apply not supported yet")
}
