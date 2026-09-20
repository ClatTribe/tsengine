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

	"github.com/ClatTribe/tsengine/internal/netguard"
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
		HTTP: netguard.GuardedClient(20 * time.Second),
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
		Meta:         map[string]string{"provider": platform.ConnOkta}, // gates which identity remediations have a live write path
		DiscoveredAt: time.Now().UTC(),
	}}, nil
}

// Watch is a no-op: identity posture is scheduled, not webhook-driven.
func (o *Okta) Watch(context.Context, platform.Connection, []byte) ([]Trigger, error) {
	return nil, nil
}

// Apply executes a gated identity remediation against the Okta org. The action
// carries a structured remediation_type + target (set by remediate/identity.go).
// Only the reversible account-suspend lifecycle transition is wired today; any
// other type returns a clear error so the HITL desk + ledger record it honestly
// rather than silently no-op'ing a "fix" that never happened.
//
// This is the only write path the connector has — it is reached ONLY after the
// HITL gate (CLAUDE.md §18.2 invariant 3): remediate.Deliverer routes an
// approved tier-≥2 ActApplyConfig identity action here. The okta.users.manage
// scope is required for a live mutation (the onboarding scopes are read-only by
// design — least privilege), so until an admin grants it Okta answers 403 and
// that surfaces as an error (the action stays un-applied, never falsely "done").
// The HTTP client is injectable (o.HTTP), so the write path is tested against a
// fake org without live admin creds.
func (o *Okta) Apply(ctx context.Context, c platform.Connection, token string, a platform.Action) error {
	// ONE source of truth with Preflight (see AWS.Apply).
	if err := o.Preflight(c, a); err != nil {
		return fmt.Errorf("okta apply: %w", err)
	}
	rt, _ := a.Payload["remediation_type"].(string)
	target, _ := a.Payload["target"].(string)
	switch rt {
	case "account_suspend":
		return o.lifecycle(ctx, token, target, "suspend")
	case "session_revoke":
		return o.revokeSessions(ctx, token, target)
	case "oauth_revoke":
		cid, _ := a.Payload["client_id"].(string)
		uids, _ := a.Payload["user_ids"].(string)
		return o.revokeGrants(ctx, token, cid, strings.Split(uids, ","))
	default:
		// Unreachable — Preflight rejects every remediation_type with no live path.
		return fmt.Errorf("okta apply: remediation_type %q has no live write path yet (target %s)", rt, target)
	}
}

// Preflight reports whether this action could actually be applied, with no network call, so the
// console can warn a human BEFORE they approve. Okta onboards with read-only scopes, so a suspend
// fails until an admin grants okta.users.manage. Grounded (§10): nil = "no known blocker".
func (o *Okta) Preflight(c platform.Connection, a platform.Action) error {
	rt, _ := a.Payload["remediation_type"].(string)
	target, _ := a.Payload["target"].(string)
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("action %s has no target", a.ID)
	}
	switch rt {
	case "account_suspend":
		return missingWriteScope(c, oktaWriteScope, "suspending "+target)
	case "session_revoke":
		return missingWriteScope(c, oktaWriteScope, "revoking the sessions of "+target)
	case "oauth_revoke":
		cid, _ := a.Payload["client_id"].(string)
		uids, _ := a.Payload["user_ids"].(string)
		if strings.TrimSpace(cid) == "" || strings.TrimSpace(uids) == "" {
			return fmt.Errorf("action %s names no client id / user ids to revoke — Okta revokes grants per user × client, and the finding did not carry them", a.ID)
		}
		return missingWriteScope(c, oktaWriteScope, "revoking the grants of "+target)
	default:
		return fmt.Errorf("remediation_type %q has no live write path yet (target %s)", rt, target)
	}
}

// lifecycle issues an Okta user-lifecycle transition (suspend/unsuspend/…).
// idOrLogin accepts the user's login (email) directly — Okta resolves it.
func (o *Okta) lifecycle(ctx context.Context, token, idOrLogin, action string) error {
	endpoint := o.OrgURL + "/api/v1/users/" + url.PathEscape(idOrLogin) + "/lifecycle/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client().Do(req)
	if err != nil {
		return fmt.Errorf("okta %s %s: %w", action, idOrLogin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("okta %s %s: http %d: %s", action, idOrLogin, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Configured reports whether this deployment supplied the OAuth credentials this
// connector needs. Without them the authorize URL would be built with an empty
// client_id and dead-end the customer on the provider's error page.
// OrgURL is required too: every Okta endpoint is relative to the org's own domain.
// revokeSessions ends every session of the user (DELETE /api/v1/users/{id}/sessions) — the
// containment for an identity-threat incident. The account stays enabled; the next request
// re-authenticates, and an attacker holding a stolen session token holds nothing.
func (o *Okta) revokeSessions(ctx context.Context, token, idOrLogin string) error {
	return o.del(ctx, token, o.OrgURL+"/api/v1/users/"+url.PathEscape(idOrLogin)+"/sessions", "revoke sessions of "+idOrLogin)
}

// revokeGrants pulls the app's OAuth grants for each named user (DELETE /api/v1/users/{uid}/
// clients/{cid}/grants). Per user × client, exactly what Okta's API grants, so the write names the
// grants the finding cited and nothing wider; one user failing does not silently skip the rest —
// every failure is collected and returned.
func (o *Okta) revokeGrants(ctx context.Context, token, clientID string, userIDs []string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("okta: oauth_revoke names no client id")
	}
	var failed []string
	revoked := 0
	for _, uid := range userIDs {
		uid = strings.TrimSpace(uid)
		if uid == "" {
			continue
		}
		if err := o.del(ctx, token, o.OrgURL+"/api/v1/users/"+url.PathEscape(uid)+"/clients/"+url.PathEscape(clientID)+"/grants", "revoke grants of "+uid); err != nil {
			failed = append(failed, uid+": "+err.Error())
			continue
		}
		revoked++
	}
	if revoked == 0 && len(failed) == 0 {
		return fmt.Errorf("okta: oauth_revoke names no user ids")
	}
	if len(failed) > 0 {
		return fmt.Errorf("okta: revoked grants for %d user(s); failed for %d: %s", revoked, len(failed), strings.Join(failed, "; "))
	}
	return nil
}

func (o *Okta) del(ctx context.Context, token, endpoint, what string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client().Do(req)
	if err != nil {
		return fmt.Errorf("okta %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("okta %s: http %d: %s", what, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (o *Okta) Configured() bool { return o.OrgURL != "" && o.ClientID != "" && o.ClientSecret != "" }
