package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/netguard"
	"github.com/ClatTribe/tsengine/internal/oidc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// sso.go is single sign-on through the workspace's own identity provider (OpenID Connect: Okta,
// Entra ID, Google Workspace, any OIDC IdP). The token verification lives in internal/oidc; this file
// decides WHO may sign in, and the decisions are refusals:
//
//   - SSO signs in EXISTING seats only. The ID token's email must be verified by the provider, must
//     belong to a user in THIS workspace, and must be the workspace the sign-in started for. There is
//     no just-in-time account creation: anyone the provider can authenticate becoming a member of a
//     security workspace is a decision for the owner, not a side effect of a login.
//   - The provider is the workspace's own, pinned by issuer. A sign-in started for workspace A can only
//     be completed by A's provider.
//   - Configuration is VERIFIED at save time (the issuer's discovery document must load and agree), so a
//     typo surfaces to the owner who made it, not to everyone at their next sign-in.
//   - An SSO session lasts 12 hours, not 30 days, so disabling someone at the identity provider takes
//     effect within a working day. An SSO login that outlived the person's IdP account would be the
//     offboarding gap SSO is bought to close.
//   - Two-factor: if the provider asserts a second factor (amr) the session satisfies the workspace
//     policy; if it does not and the person has their own authenticator, they are asked for it. SSO
//     never becomes a way around a second factor the person has set up.
//   - Enforcement keeps the OWNER's password: an unavailable or misconfigured provider must not lock a
//     workspace out of itself. Every other seat signs in through the provider.
//   - The flow state (PKCE verifier, nonce) is held server-side as a single-use, ten-minute record the
//     auth gate refuses, never in the URL.

const (
	ssoSessionTTL = 12 * time.Hour
	ssoFlowTTL    = 10 * time.Minute
)

// ssoHTTP is the outbound client for provider metadata, keys and token exchange. It refuses private
// and metadata addresses, because the issuer URL is customer-supplied (netguard). Tests override it.
var ssoHTTP = func() *http.Client { return netguard.GuardedClient(10 * time.Second) }

// ssoRedirectURI is where the provider returns the browser: the app's own callback route.
func (d Deps) ssoRedirectURI() string {
	return strings.TrimRight(d.AppURL, "/") + "/api/sso/callback"
}

type ssoView struct {
	Configured   bool   `json:"configured"`
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	HasSecret    bool   `json:"has_secret"`
	Enforced     bool   `json:"enforced"`
	ConfiguredBy string `json:"configured_by,omitempty"`
	RedirectURI  string `json:"redirect_uri"` // what the owner registers at their provider
}

func (d Deps) ssoViewFor(t platform.Tenant) ssoView {
	v := ssoView{RedirectURI: d.ssoRedirectURI()}
	if t.SSO != nil {
		v.Configured = true
		v.Issuer, v.ClientID, v.HasSecret = t.SSO.Issuer, t.SSO.ClientID, t.SSO.ClientSecretRef != ""
		v.Enforced, v.ConfiguredBy = t.SSO.Enforced, t.SSO.ConfiguredBy
	}
	return v
}

func (d Deps) handleGetSSO(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	writeJSON(w, http.StatusOK, d.ssoViewFor(t))
}

// handlePutSSO saves (or with an empty issuer, removes) the workspace's provider. Owner-only by the
// settings prefix. The issuer is checked against the provider's own metadata before anything is saved.
func (d Deps) handlePutSSO(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"` // empty keeps the stored one
		Enforced     bool   `json:"enforced"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("tenant not found"))
		return
	}
	actor := "platform operator"
	if s, ok := d.resolveSession(r); ok {
		if u, uerr := d.Store.GetUser(r.Context(), s.UserID); uerr == nil {
			actor = u.Email
		}
	}
	if strings.TrimSpace(body.Issuer) == "" {
		t.SSO = nil
		if err := d.Store.PutTenant(r.Context(), t); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
			return
		}
		d.recordSSO("single sign-on removed", tenantID, actor)
		writeJSON(w, http.StatusOK, d.ssoViewFor(t))
		return
	}
	if d.Vault == nil {
		writeJSON(w, http.StatusNotImplemented, errCode("single sign-on needs TSENGINE_SECRET_KEY set on the platform, so the client secret can be encrypted at rest", "no_vault"))
		return
	}
	if strings.TrimSpace(body.ClientID) == "" {
		writeJSON(w, http.StatusBadRequest, errBody("the client ID from your identity provider is required"))
		return
	}
	cfg := platform.SSOConfig{Issuer: strings.TrimRight(strings.TrimSpace(body.Issuer), "/"), ClientID: strings.TrimSpace(body.ClientID),
		Enforced: body.Enforced, ConfiguredBy: actor, ConfiguredAt: time.Now().UTC()}
	if t.SSO != nil {
		cfg.ClientSecretRef = t.SSO.ClientSecretRef
	}
	if sec := strings.TrimSpace(body.ClientSecret); sec != "" {
		ref, serr := d.Vault.Seal(sec)
		if serr != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("could not store the client secret"))
			return
		}
		cfg.ClientSecretRef = ref
	}
	if cfg.ClientSecretRef == "" {
		writeJSON(w, http.StatusBadRequest, errBody("the client secret from your identity provider is required"))
		return
	}
	// Verify NOW, against the provider's own metadata, so a mistake reaches the person who made it.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, derr := oidc.Discover(ctx, ssoHTTP(), cfg.Issuer); derr != nil {
		writeJSON(w, http.StatusBadRequest, errCode("could not reach that identity provider's sign-in metadata: "+derr.Error()+
			" — check the issuer URL (for Okta it looks like https://acme.okta.com; for Entra ID, https://login.microsoftonline.com/<tenant-id>/v2.0)",
			"sso_discovery_failed"))
		return
	}
	t.SSO = &cfg
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordSSO("single sign-on configured", tenantID, actor)
	writeJSON(w, http.StatusOK, d.ssoViewFor(t))
}

func (d Deps) recordSSO(what, tenantID, actor string) {
	if d.Recorder != nil {
		d.Recorder.Record(what, "auth", map[string]any{"tenant_id": tenantID, "by": actor}, "workspace sign-in")
	}
}

// ssoFor finds the workspace an email signs in to and its provider. Emails are globally unique, so the
// person's own seat names the workspace: no domain needs to be claimed, and no workspace can route
// another's people to its provider.
func (d Deps) ssoFor(ctx context.Context, email string) (platform.User, platform.Tenant, bool) {
	u, err := d.Store.GetUserByEmail(ctx, email)
	if err != nil {
		return platform.User{}, platform.Tenant{}, false
	}
	t, err := d.Store.GetTenant(ctx, u.TenantID)
	if err != nil || t.SSO == nil {
		return u, t, false
	}
	return u, t, true
}

// handleSSOStart begins a sign-in for an email. The answer only says whether SSO applies, never
// whether an account exists (an unknown email and a password account answer the same).
func (d Deps) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	_, t, ok := d.ssoFor(r.Context(), email)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"sso": false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, ssoHTTP(), t.SSO.Issuer)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errCode("your workspace's identity provider is not reachable right now: "+err.Error(), "sso_unavailable"))
		return
	}
	state, err1 := oidc.Random()
	nonce, err2 := oidc.Random()
	verifier, err3 := oidc.Random()
	if err := errors.Join(err1, err2, err3); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not start sign-in"))
		return
	}
	if err := d.Store.PutSession(r.Context(), platform.Session{Token: state, TenantID: t.ID, ExpiresAt: time.Now().Add(ssoFlowTTL),
		SSOFlow: &platform.SSOFlow{Verifier: verifier, Nonce: nonce, Email: email}}); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sso": true,
		"authorize_url": p.AuthURL(t.SSO.ClientID, d.ssoRedirectURI(), state, nonce, verifier, email)})
}

// handleSSOCallback completes a sign-in: exchange the code, verify the ID token, match the seat.
func (d Deps) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	refuse := func(msg, code string) { writeJSON(w, http.StatusUnauthorized, errCode(msg, code)) }
	flow, err := d.Store.GetSession(r.Context(), strings.TrimSpace(body.State))
	if err != nil || flow.SSOFlow == nil || !time.Now().Before(flow.ExpiresAt) {
		refuse("this sign-in has expired or was already used — start again", "sso_expired")
		return
	}
	_ = d.Store.DeleteSession(r.Context(), flow.Token) // single use, whatever happens next
	t, err := d.Store.GetTenant(r.Context(), flow.TenantID)
	if err != nil || t.SSO == nil || d.Vault == nil {
		refuse("single sign-on is no longer configured for this workspace", "sso_not_configured")
		return
	}
	secret, err := d.Vault.Open(t.SSO.ClientSecretRef)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not read the stored client secret"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, ssoHTTP(), t.SSO.Issuer)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errCode("your identity provider is not reachable right now", "sso_unavailable"))
		return
	}
	raw, err := p.Exchange(ctx, t.SSO.ClientID, secret, d.ssoRedirectURI(), body.Code, flow.SSOFlow.Verifier)
	if err != nil {
		refuse("your identity provider refused the sign-in: "+err.Error(), "sso_exchange_failed")
		return
	}
	claims, err := p.Verify(ctx, raw, t.SSO.ClientID, flow.SSOFlow.Nonce, time.Now())
	if err != nil {
		refuse("the sign-in could not be verified: "+err.Error(), "sso_invalid_token")
		return
	}
	if !claims.EmailVerified || claims.Email == "" {
		refuse("your identity provider did not confirm your email address, so it cannot be matched to an account", "sso_email_unverified")
		return
	}
	u, err := d.Store.GetUserByEmail(r.Context(), claims.Email)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && u.TenantID != t.ID:
		refuse(claims.Email+" does not have a seat in this workspace — ask its owner to invite you", "sso_no_seat")
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	case u.Disabled:
		refuse("this account was deactivated by your organisation's identity provider", "account_disabled")
		return
	}
	// The person's own authenticator is never bypassed by SSO: without a provider-asserted second
	// factor, they are asked for it as they would be at the password door.
	if u.TwoFactorEnabled && !claims.MFA() {
		d.startSecondFactor(w, r, u)
		return
	}
	tok, err := authn.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("could not start a session"))
		return
	}
	sess := platform.Session{Token: tok, UserID: u.ID, TenantID: u.TenantID, ExpiresAt: time.Now().Add(ssoSessionTTL),
		Via: "sso", IdPMFA: claims.MFA()}
	if err := d.Store.PutSession(r.Context(), sess); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	d.recordSSO("signed in with single sign-on", t.ID, u.Email)
	u.PasswordHash = ""
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "tenant": u.TenantID, "user": u})
}

// ssoEnforcedFor reports whether password sign-in is closed to this person (every seat but the owner,
// when the workspace enforces SSO).
func (d Deps) ssoEnforcedFor(ctx context.Context, u platform.User) bool {
	if u.Role == platform.RoleOwner {
		return false
	}
	t, err := d.Store.GetTenant(ctx, u.TenantID)
	return err == nil && t.SSO != nil && t.SSO.Enforced
}
