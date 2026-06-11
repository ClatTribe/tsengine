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

// Okta is the OAuth onboarding connector for an Okta org — it lets a non-tech tenant
// connect their IdP so the operate posture engine can assess identity hygiene (MFA,
// stale/over-privileged accounts). Unlike Google/Microsoft, an Okta authorization server
// lives at the customer's own org domain, so OrgURL is set per deployment (one Okta org
// per platform instance, like the single OAuth app the other connectors use).
//
// Discover yields a single "workspace" asset; the live directory fetch lives in
// internal/operate (Okta.Fetch). Watch is a no-op (posture is scheduled); Apply is
// unsupported for now (identity remediation is future work).
type Okta struct {
	OrgURL       string // e.g. https://dev-12345.okta.com (no trailing slash)
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

// NewOkta builds the connector. orgURL is the tenant's Okta org base URL.
func NewOkta(orgURL, clientID, clientSecret string) *Okta {
	return &Okta{
		OrgURL: strings.TrimRight(orgURL, "/"), ClientID: clientID, ClientSecret: clientSecret,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func (o *Okta) Kind() string { return platform.ConnOkta }

func (o *Okta) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return http.DefaultClient
}

// oktaScopes: read-only directory + factor + role scopes — exactly what the posture
// fetch needs, nothing more (least privilege).
const oktaScopes = "okta.users.read okta.factors.read okta.roles.read"

func (o *Okta) OAuthURL(state, redirectURI string) string {
	q := url.Values{
		"client_id":     {o.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid " + oktaScopes},
		"state":         {state},
	}
	return o.OrgURL + "/oauth2/v1/authorize?" + q.Encode()
}

func (o *Okta) Exchange(ctx context.Context, code, redirectURI string) (platform.Connection, error) {
	form := url.Values{
		"client_id":     {o.ClientID},
		"client_secret": {o.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.OrgURL+"/oauth2/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return platform.Connection{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.client().Do(req)
	if err != nil {
		return platform.Connection{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return platform.Connection{}, fmt.Errorf("okta: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return platform.Connection{}, fmt.Errorf("okta: oauth exchange failed: %s", nz(tok.Error, "no token"))
	}
	// SecretRef carries the RAW token transiently; the caller seals it before persisting.
	return platform.Connection{
		Kind: platform.ConnOkta, Status: platform.ConnActive,
		Scopes: strings.Fields(oktaScopes), CreatedAt: time.Now().UTC(),
		SecretRef: tok.AccessToken,
	}, nil
}

// Discover returns the single workspace asset the operate engine assesses.
func (o *Okta) Discover(_ context.Context, c platform.Connection, _ string) ([]platform.Asset, error) {
	return []platform.Asset{{
		TenantID: c.TenantID, ConnectionID: c.ID,
		Type:         "workspace",
		Target:       nz(c.Account, "okta"),
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: identity posture is scheduled, not webhook-driven.
func (o *Okta) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply is unsupported today (autonomous identity remediation is future work).
func (o *Okta) Apply(context.Context, platform.Connection, string, platform.Action) error {
	return fmt.Errorf("okta: apply not supported yet")
}
