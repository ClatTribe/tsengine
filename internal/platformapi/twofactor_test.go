package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/totp"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type tfa struct {
	t   *testing.T
	h   http.Handler
	st  store.Store
	sec string // the seed as the authenticator app holds it
}

func vaultForTest(t *testing.T) Sealer {
	t.Helper()
	v, err := secret.NewAESGCM([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newTFA(t *testing.T, st store.Store, vault Sealer) *tfa {
	t.Helper()
	ctx := context.Background()
	hash, _ := authn.HashPassword("correct-horse-1")
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ada@acme.example", Role: platform.RoleOwner, PasswordHash: hash})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	if vault != nil {
		d.Vault = vault
	}
	return &tfa{t: t, h: NewHandler(d), st: st}
}

// call issues a request with a session bearer (or none).
func (x *tfa) call(method, path, bearer, body string) (int, map[string]any) {
	x.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	x.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (x *tfa) login() map[string]any {
	x.t.Helper()
	code, out := x.call("POST", "/v1/auth/login", "", `{"email":"ada@acme.example","password":"correct-horse-1"}`)
	if code != 200 {
		x.t.Fatalf("login → %d %v", code, out)
	}
	return out
}

// enable runs setup + confirm and returns the session token and the recovery codes.
func (x *tfa) enable() (string, []string) {
	x.t.Helper()
	tok := x.login()["token"].(string)
	code, out := x.call("POST", "/v1/auth/2fa/setup", tok, `{"password":"correct-horse-1"}`)
	if code != 200 {
		x.t.Fatalf("setup → %d %v", code, out)
	}
	x.sec = out["secret"].(string)
	c, _ := totp.Code(x.sec, time.Now())
	code, out = x.call("POST", "/v1/auth/2fa/enable", tok, `{"code":"`+c+`"}`)
	if code != 200 {
		x.t.Fatalf("enable → %d %v", code, out)
	}
	var rc []string
	for _, v := range out["recovery_codes"].([]any) {
		rc = append(rc, v.(string))
	}
	return tok, rc
}

// nextCode returns a valid code at a step the server has not yet accepted (the next step), so a test
// can sign in twice without tripping replay protection.
func (x *tfa) nextCode() string {
	c, _ := totp.Code(x.sec, time.Now().Add(totp.Period*time.Second))
	return c
}

// THE property: once 2FA is on, the password alone opens nothing.
func TestTwoFactor_PasswordAloneOpensNothing(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	x.enable()
	out := x.login()
	if out["token"] != nil {
		t.Fatalf("a correct password returned a session token with 2FA on: %v", out)
	}
	if out["two_factor_required"] != true {
		t.Fatalf("login did not ask for the second factor: %v", out)
	}
	half := out["challenge"].(string)
	for _, p := range []struct{ method, path string }{
		{"GET", "/v1/auth/me"}, {"GET", "/v1/findings"}, {"GET", "/v1/issues"},
		{"POST", "/v1/auth/2fa/disable"}, {"POST", "/v1/rescan"},
	} {
		if code, _ := x.call(p.method, p.path, half, `{}`); code != http.StatusUnauthorized {
			t.Errorf("%s %s with a half-session → %d, want 401", p.method, p.path, code)
		}
	}
	code, done := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`)
	if code != 200 || done["token"] == nil {
		t.Fatalf("verify → %d %v", code, done)
	}
	if code, _ := x.call("GET", "/v1/auth/me", done["token"].(string), ""); code != 200 {
		t.Errorf("the redeemed session does not work: %d", code)
	}
	// The half-session is single use.
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`); code != 401 {
		t.Errorf("a redeemed challenge was accepted again: %d", code)
	}
}

func TestTwoFactor_CodeCannotBeReplayed(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	x.enable()
	c := x.nextCode()
	half := x.login()["challenge"].(string)
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+c+`"}`); code != 200 {
		t.Fatalf("first use of a code → %d", code)
	}
	half2 := x.login()["challenge"].(string)
	if code, out := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half2+`","code":"`+c+`"}`); code != 401 {
		t.Errorf("the same code worked twice (observed-code replay): %d %v", code, out)
	}
}

func TestTwoFactor_FiveWrongCodesBurnTheSignIn(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	x.enable()
	half := x.login()["challenge"].(string)
	var last map[string]any
	for i := 0; i < maxMFAAttempts; i++ {
		_, last = x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"000000"}`)
	}
	if last["code"] != "two_factor_locked" {
		t.Errorf("after %d wrong codes the reason is %v, want two_factor_locked", maxMFAAttempts, last["code"])
	}
	// Even the RIGHT code no longer works on that challenge: the password is needed again.
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`); code != 401 {
		t.Errorf("a burned challenge accepted a valid code: %d", code)
	}
}

func TestTwoFactor_RecoveryCodeWorksOnce(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	_, rc := x.enable()
	half := x.login()["challenge"].(string)
	code, out := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","recovery_code":"`+strings.ToUpper(rc[0])+`"}`)
	if code != 200 || out["recovery_codes_remaining"] != float64(totp.RecoveryCount-1) {
		t.Fatalf("recovery sign-in → %d %v", code, out)
	}
	half = x.login()["challenge"].(string)
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","recovery_code":"`+rc[0]+`"}`); code != 401 {
		t.Errorf("a recovery code worked twice: %d", code)
	}
	_, me := x.call("GET", "/v1/auth/me", out["token"].(string), "")
	if me["recovery_codes_remaining"] != float64(totp.RecoveryCount-1) || me["two_factor_enabled"] != true {
		t.Errorf("/me does not report the 2FA state: %v", me)
	}
}

// Turning it on from setup alone would lock out anyone whose scan did not take.
func TestTwoFactor_NotOnUntilAuthenticatorProved(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	tok := x.login()["token"].(string)
	if code, _ := x.call("POST", "/v1/auth/2fa/setup", tok, `{"password":"wrong-password"}`); code != 401 {
		t.Errorf("setup without the password → %d, want 401", code)
	}
	_, out := x.call("POST", "/v1/auth/2fa/setup", tok, `{"password":"correct-horse-1"}`)
	if code, _ := x.call("POST", "/v1/auth/2fa/enable", tok, `{"code":"000000"}`); code != 400 {
		t.Errorf("enable with a wrong code → %d, want 400", code)
	}
	u, _ := x.st.GetUser(context.Background(), "u1")
	if u.TwoFactorEnabled {
		t.Fatal("2FA turned on without a verified code")
	}
	if l := x.login(); l["token"] == nil {
		t.Error("an unconfirmed setup changed how sign-in works")
	}
	if out["secret"] == nil || !strings.HasPrefix(out["uri"].(string), "otpauth://totp/") {
		t.Errorf("setup did not return an importable key: %v", out)
	}
}

func TestTwoFactor_SeedIsSealedAndNeverReturnedAgain(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	tok, _ := x.enable()
	u, _ := x.st.GetUser(context.Background(), "u1")
	if u.TOTPSecretRef == "" || u.TOTPSecretRef == x.sec || strings.Contains(u.TOTPSecretRef, x.sec) {
		t.Errorf("the authenticator seed is stored in plaintext: %q", u.TOTPSecretRef)
	}
	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	x.h.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, leak := range []string{x.sec, u.TOTPSecretRef, "recovery_hashes", "totp_"} {
		if strings.Contains(body, leak) {
			t.Errorf("/me leaks %q: %s", leak, body)
		}
	}
}

func TestTwoFactor_SetupRefusedWithoutAVault(t *testing.T) {
	x := newTFA(t, store.NewMemory(), nil)
	tok := x.login()["token"].(string)
	code, out := x.call("POST", "/v1/auth/2fa/setup", tok, `{"password":"correct-horse-1"}`)
	if code != http.StatusNotImplemented || out["code"] != "no_vault" {
		t.Errorf("setup with no vault → %d %v; it must refuse rather than store a seed in plaintext", code, out)
	}
}

// A session opened before the second factor existed must not outlive it.
func TestTwoFactor_EnableSignsOutOtherSessions(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	other := x.login()["token"].(string)
	tok, _ := x.enable()
	if code, _ := x.call("GET", "/v1/auth/me", other, ""); code != 401 {
		t.Errorf("a session from before 2FA still works: %d", code)
	}
	if code, _ := x.call("GET", "/v1/auth/me", tok, ""); code != 200 {
		t.Errorf("the session that turned 2FA on was signed out: %d", code)
	}
}

func TestTwoFactor_DisableNeedsPasswordAndCode(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	tok, _ := x.enable()
	if code, _ := x.call("POST", "/v1/auth/2fa/disable", tok, `{"password":"correct-horse-1"}`); code != 401 {
		t.Errorf("disable with the password but no code → %d, want 401", code)
	}
	if code, _ := x.call("POST", "/v1/auth/2fa/disable", tok, `{"password":"nope","code":"`+x.nextCode()+`"}`); code != 401 {
		t.Errorf("disable with a code but the wrong password → %d, want 401", code)
	}
	if code, _ := x.call("POST", "/v1/auth/2fa/disable", tok, `{"password":"correct-horse-1","code":"`+x.nextCode()+`"}`); code != 200 {
		t.Fatalf("disable with both → %d", code)
	}
	u, _ := x.st.GetUser(context.Background(), "u1")
	if u.TwoFactorEnabled || u.TOTPSecretRef != "" || len(u.RecoveryHashes) != 0 {
		t.Errorf("disable left 2FA material behind: %+v", u)
	}
}

// Reset proves control of the mailbox; the second factor exists for the day the mailbox was taken.
func TestTwoFactor_PasswordResetDoesNotRemoveIt(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	x.enable()
	u, _ := x.st.GetUser(context.Background(), "u1")
	u.ResetTokenHash, u.ResetTokenExpires = sha256hex("reset-tok"), time.Now().Add(time.Hour)
	_ = x.st.PutUser(context.Background(), u)
	if code, out := x.call("POST", "/v1/auth/reset", "", `{"email":"ada@acme.example","token":"reset-tok","new_password":"another-horse-2"}`); code != 200 {
		t.Fatalf("reset → %d %v", code, out)
	}
	_, out := x.call("POST", "/v1/auth/login", "", `{"email":"ada@acme.example","password":"another-horse-2"}`)
	if out["token"] != nil || out["two_factor_required"] != true {
		t.Errorf("after a password reset the new password alone signed in: %v", out)
	}
}

// The seed, last step and recovery codes must survive the production store (UserRecord).
func TestTwoFactor_WorksOnSQLite(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	x := newTFA(t, st, vaultForTest(t))
	_, rc := x.enable()
	half := x.login()["challenge"].(string)
	if code, out := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`); code != 200 {
		t.Fatalf("verify on SQLite → %d %v (the seed did not survive the store?)", code, out)
	}
	half = x.login()["challenge"].(string)
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","recovery_code":"`+rc[1]+`"}`); code != 200 {
		t.Errorf("recovery code on SQLite → %d", code)
	}
}
