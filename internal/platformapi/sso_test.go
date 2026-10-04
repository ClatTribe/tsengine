package platformapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// ssoIdP is a minimal OpenID provider: discovery, one RS256 key, and a token endpoint that mints
// whatever claims the test sets for the next exchange.
type ssoIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	claims map[string]any
}

func newSSOIdP(t *testing.T) *ssoIdP {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &ssoIdP{key: k}
	mux := http.NewServeMux()
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b.EncodeToString(k.N.Bytes()), "e": b.EncodeToString([]byte{1, 0, 1})}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "good-code" || r.Form.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		c := f.claims
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(c)})
	})
	prev := ssoHTTP
	ssoHTTP = func() *http.Client { return f.srv.Client() }
	t.Cleanup(func() { ssoHTTP = prev })
	return f
}

func (f *ssoIdP) sign(c map[string]any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	head, body := enc(map[string]string{"alg": "RS256", "kid": "k1"}), enc(c)
	d := sha256.Sum256([]byte(head + "." + body))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, d[:])
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type ssoEnv struct {
	*tfa
	idp *ssoIdP
}

// newSSOEnv: workspace t1 with owner ada (password correct-horse-1) and member bo, SSO configured.
func newSSOEnv(t *testing.T, enforced bool) *ssoEnv {
	t.Helper()
	st := store.NewMemory()
	idp := newSSOIdP(t)
	hash, _ := authn.HashPassword("correct-horse-1")
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t2", Name: "Other"})
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ada@acme.example", Role: platform.RoleOwner, PasswordHash: hash})
	_ = st.PutUser(ctx, platform.User{ID: "u2", TenantID: "t1", Email: "bo@acme.example", Role: platform.RoleMember, PasswordHash: hash})
	_ = st.PutUser(ctx, platform.User{ID: "u3", TenantID: "t2", Email: "cy@other.example", Role: platform.RoleMember, PasswordHash: hash})
	x := &tfa{t: t, st: st, h: NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		Vault: vaultForTest(t), AppURL: "https://app.example"})}
	e := &ssoEnv{tfa: x, idp: idp}
	owner := x.login()["token"].(string)
	body, _ := json.Marshal(map[string]any{"issuer": idp.srv.URL, "client_id": "client-1", "client_secret": "s3cret", "enforced": enforced})
	if code, out := x.call("PUT", "/v1/settings/sso", owner, string(body)); code != 200 {
		t.Fatalf("configure SSO → %d %v", code, out)
	}
	return e
}

// start begins SSO for an email and returns the state and nonce the authorize URL carries.
func (e *ssoEnv) start(email string) (state, nonce string) {
	e.t.Helper()
	code, out := e.call("POST", "/v1/auth/sso/start", "", `{"email":"`+email+`"}`)
	if code != 200 || out["sso"] != true {
		e.t.Fatalf("sso start for %s → %d %v", email, code, out)
	}
	u, _ := url.Parse(out["authorize_url"].(string))
	q := u.Query()
	if q.Get("redirect_uri") != "https://app.example/api/sso/callback" || q.Get("client_id") != "client-1" {
		e.t.Errorf("authorize URL: %s", u)
	}
	return q.Get("state"), q.Get("nonce")
}

func (e *ssoEnv) mint(email string, verified bool, nonce string, amr ...string) {
	e.idp.mu.Lock()
	defer e.idp.mu.Unlock()
	e.idp.claims = map[string]any{"iss": e.idp.srv.URL, "aud": "client-1", "sub": "idp-" + email, "email": email,
		"email_verified": verified, "nonce": nonce, "exp": time.Now().Add(5 * time.Minute).Unix(), "amr": amr}
}

func (e *ssoEnv) callback(state string) (int, map[string]any) {
	return e.call("POST", "/v1/auth/sso/callback", "", `{"code":"good-code","state":"`+state+`"}`)
}

func TestSSO_SignsInAnExistingSeatWithAShortSession(t *testing.T) {
	e := newSSOEnv(t, false)
	state, nonce := e.start("bo@acme.example")
	e.mint("bo@acme.example", true, nonce, "pwd")
	code, out := e.callback(state)
	if code != 200 || out["token"] == nil {
		t.Fatalf("SSO callback → %d %v", code, out)
	}
	sess, _ := e.st.GetSession(context.Background(), out["token"].(string))
	if sess.Via != "sso" || sess.UserID != "u2" || time.Until(sess.ExpiresAt) > 13*time.Hour {
		t.Errorf("SSO session = %+v; want via sso, user u2, ~12h", sess)
	}
	if code, _ := e.call("GET", "/v1/findings", out["token"].(string), ""); code != 200 {
		t.Errorf("the SSO session does not work: %d", code)
	}
	// The state is single use.
	if code, _ := e.callback(state); code != http.StatusUnauthorized {
		t.Errorf("an SSO state was redeemed twice: %d", code)
	}
}

func TestSSO_RefusesWhoItShould(t *testing.T) {
	e := newSSOEnv(t, false)
	for name, c := range map[string]struct {
		email    string
		verified bool
		want     string
	}{
		"unverified email":          {"bo@acme.example", false, "sso_email_unverified"},
		"no seat anywhere":          {"stranger@acme.example", true, "sso_no_seat"},
		"seat in another workspace": {"cy@other.example", true, "sso_no_seat"},
	} {
		state, nonce := e.start("bo@acme.example")
		e.mint(c.email, c.verified, nonce)
		code, out := e.callback(state)
		if code != http.StatusUnauthorized || out["code"] != c.want {
			t.Errorf("%s: → %d %v, want 401 %s", name, code, out, c.want)
		}
	}
	// A token minted for a different sign-in (wrong nonce) is refused.
	state, _ := e.start("bo@acme.example")
	e.mint("bo@acme.example", true, "some-other-nonce")
	if code, out := e.callback(state); code != http.StatusUnauthorized || out["code"] != "sso_invalid_token" {
		t.Errorf("a token for another sign-in → %d %v", code, out)
	}
}

// The in-flight state authenticates nothing.
func TestSSO_FlowStateIsNotASession(t *testing.T) {
	e := newSSOEnv(t, false)
	state, _ := e.start("bo@acme.example")
	if code, _ := e.call("GET", "/v1/auth/me", state, ""); code != http.StatusUnauthorized {
		t.Errorf("an in-flight SSO state was accepted as a session: %d", code)
	}
}

// Start says only whether SSO applies — an unknown email and a workspace without SSO answer the same.
func TestSSO_StartDoesNotEnumerate(t *testing.T) {
	e := newSSOEnv(t, false)
	_, a := e.call("POST", "/v1/auth/sso/start", "", `{"email":"nobody@nowhere.example"}`)
	_, b := e.call("POST", "/v1/auth/sso/start", "", `{"email":"cy@other.example"}`)
	if a["sso"] != false || b["sso"] != false || len(a) != len(b) {
		t.Errorf("start distinguishes an unknown email from a seat without SSO: %v vs %v", a, b)
	}
}

// Enforcement closes the password door to every seat but the owner's.
func TestSSO_EnforcementKeepsTheOwnersBreakGlass(t *testing.T) {
	e := newSSOEnv(t, true)
	code, out := e.call("POST", "/v1/auth/login", "", `{"email":"bo@acme.example","password":"correct-horse-1"}`)
	if code != http.StatusForbidden || out["code"] != "sso_required" {
		t.Errorf("a member signed in with a password under SSO enforcement: %d %v", code, out)
	}
	if l := e.login(); l["token"] == nil {
		t.Error("the owner's break-glass password was refused under SSO enforcement")
	}
}

// SSO never routes around the person's own authenticator, and a provider-asserted factor satisfies
// the workspace policy.
func TestSSO_AndTwoFactor(t *testing.T) {
	e := newSSOEnv(t, false)
	// The owner turns on their own authenticator, then the policy.
	owner, _ := e.enable()
	if code, _ := e.call("PUT", "/v1/settings/security", owner, `{"require_two_factor":true}`); code != 200 {
		t.Fatal("could not require two-factor")
	}
	// Ada (has TOTP) through SSO WITHOUT a provider factor: asked for her code.
	state, nonce := e.start("ada@acme.example")
	e.mint("ada@acme.example", true, nonce, "pwd")
	_, out := e.callback(state)
	if out["token"] != nil || out["two_factor_required"] != true {
		t.Errorf("SSO bypassed the owner's own authenticator: %v", out)
	}
	// Bo (no TOTP) through SSO WITH a provider factor: let in, policy satisfied by the provider.
	state, nonce = e.start("bo@acme.example")
	e.mint("bo@acme.example", true, nonce, "pwd", "mfa")
	_, out = e.callback(state)
	tok, _ := out["token"].(string)
	if code, _ := e.call("GET", "/v1/findings", tok, ""); code != 200 {
		t.Errorf("a provider-asserted second factor did not satisfy the workspace policy: %d", code)
	}
	_, me := e.call("GET", "/v1/auth/me", tok, "")
	if me["two_factor_required"] == true {
		t.Error("/me sends a provider-MFA session to enrolment")
	}
	// Bo WITHOUT a provider factor: gated to enrolment like a password sign-in.
	state, nonce = e.start("bo@acme.example")
	e.mint("bo@acme.example", true, nonce, "pwd")
	_, out = e.callback(state)
	tok, _ = out["token"].(string)
	if code, out := e.call("GET", "/v1/findings", tok, ""); code != http.StatusForbidden || out["code"] != "two_factor_setup_required" {
		t.Errorf("an SSO sign-in without any second factor passed the policy: %d %v", code, out)
	}
}

// A wrong issuer is caught when the owner saves it, not at everyone's next sign-in; the secret never
// comes back.
func TestSSO_ConfigIsVerifiedAndTheSecretNeverReturned(t *testing.T) {
	e := newSSOEnv(t, false)
	owner := e.login()["token"].(string)
	code, out := e.call("PUT", "/v1/settings/sso", owner, `{"issuer":"https://127.0.0.1:1/nope","client_id":"c","client_secret":"x"}`)
	if code != http.StatusBadRequest || out["code"] != "sso_discovery_failed" {
		t.Errorf("an unreachable issuer was saved: %d %v", code, out)
	}
	ten, _ := e.st.GetTenant(context.Background(), "t1")
	if ten.SSO == nil || ten.SSO.Issuer != e.idp.srv.URL {
		t.Error("a refused save changed the stored configuration")
	}
	for _, path := range []string{"/v1/settings/sso", "/v1/tenant"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+owner)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), "s3cret") || strings.Contains(rec.Body.String(), ten.SSO.ClientSecretRef) {
			t.Errorf("%s exposes the client secret: %s", path, rec.Body.String())
		}
	}
	// A member cannot change how the workspace signs in.
	member := e.memberToken()
	if code, _ := e.call("PUT", "/v1/settings/sso", member, `{"issuer":""}`); code != http.StatusForbidden {
		t.Errorf("a member removed SSO: %d", code)
	}
}

func (e *ssoEnv) memberToken() string {
	e.t.Helper()
	code, out := e.call("POST", "/v1/auth/login", "", `{"email":"bo@acme.example","password":"correct-horse-1"}`)
	if code != 200 {
		e.t.Fatalf("member login → %d %v", code, out)
	}
	return out["token"].(string)
}
