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
	GraphBase    string // Microsoft Graph base; default https://graph.microsoft.com/v1.0 (overridable for tests)
	HTTP         *http.Client
}

// NewM365 builds the connector with production defaults.
func NewM365(clientID, clientSecret string) *M365 {
	return &M365{
		ClientID: clientID, ClientSecret: clientSecret, Tenant: "common",
		OAuthBase: "https://login.microsoftonline.com",
		GraphBase: "https://graph.microsoft.com/v1.0",
		HTTP:      &http.Client{Timeout: 20 * time.Second},
	}
}

func (m *M365) graphBase() string {
	if m.GraphBase == "" {
		return "https://graph.microsoft.com/v1.0"
	}
	return strings.TrimRight(m.GraphBase, "/")
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
// Apply executes a gated identity remediation against Microsoft 365 / Entra ID. Reached only after
// the HITL gate (§18.2 inv. 3). Today: account_suspend → disable sign-in (accountEnabled=false), the
// reversible fix for a stale/over-privileged account. It needs the User.ReadWrite.All WRITE scope —
// the onboarding scope is read-only by design, so a real disable requires an admin to grant the write
// scope; until then Graph returns 403 and Apply surfaces it honestly (never falsely "done").
func (m *M365) Apply(ctx context.Context, _ platform.Connection, token string, a platform.Action) error {
	rt, _ := a.Payload["remediation_type"].(string)
	target := strFrom(a.Payload, "target")
	switch rt {
	case "account_suspend":
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("m365 apply: action %s has no target user", a.ID)
		}
		return m.disableUser(ctx, token, target)
	default:
		return fmt.Errorf("m365 apply: remediation_type %q has no live write path yet (target %s)", rt, target)
	}
}

// disableUser sets accountEnabled=false on an Entra user (Microsoft Graph). userID accepts the
// object id or the userPrincipalName (email) directly.
func (m *M365) disableUser(ctx context.Context, token, userID string) error {
	endpoint := m.graphBase() + "/users/" + url.PathEscape(userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, strings.NewReader(`{"accountEnabled":false}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("m365 disable %s: %w", userID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("m365 disable %s: HTTP %d: %s (needs the User.ReadWrite.All write scope)", userID, resp.StatusCode, body)
	}
	return nil
}
