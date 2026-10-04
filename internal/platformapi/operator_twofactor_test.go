package platformapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/totp"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func newOpTFA(t *testing.T, require bool) *tfa {
	t.Helper()
	st := store.NewMemory()
	hash, _ := authn.HashPassword("correct-horse-1")
	_ = st.PutOperator(context.Background(), platform.Operator{ID: "op-1", Email: "pat@msp.example", PasswordHash: hash})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", Vault: vaultForTest(t), OperatorRequire2FA: require}
	return &tfa{t: t, h: NewHandler(d), st: st}
}

func (x *tfa) opLogin() map[string]any {
	x.t.Helper()
	code, out := x.call("POST", "/v1/operator/login", "", `{"email":"pat@msp.example","password":"correct-horse-1"}`)
	if code != 200 {
		x.t.Fatalf("operator login → %d %v", code, out)
	}
	return out
}

func (x *tfa) opEnable() string {
	x.t.Helper()
	tok := x.opLogin()["token"].(string)
	code, out := x.call("POST", "/v1/operator/2fa/setup", tok, `{"password":"correct-horse-1"}`)
	if code != 200 {
		x.t.Fatalf("operator setup → %d %v", code, out)
	}
	x.sec = out["secret"].(string)
	c, _ := totp.Code(x.sec, time.Now())
	if code, out := x.call("POST", "/v1/operator/2fa/enable", tok, `{"code":"`+c+`"}`); code != 200 {
		x.t.Fatalf("operator enable → %d %v", code, out)
	}
	return tok
}

// The operator credential reaches every client on the roster; the password alone must open none of it.
func TestOperatorTwoFactor_PasswordAloneOpensNothing(t *testing.T) {
	x := newOpTFA(t, false)
	x.opEnable()
	out := x.opLogin()
	if out["token"] != nil || out["two_factor_required"] != true {
		t.Fatalf("operator login with 2FA on returned a session: %v", out)
	}
	half := out["challenge"].(string)
	for _, p := range []string{"/v1/operator/me", "/v1/operator/queue"} {
		if code, _ := x.call("GET", p, half, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s with an operator half-session → %d, want 401", p, code)
		}
	}
	// A TENANT half-session endpoint must not redeem an operator challenge: the namespaces never cross.
	if code, _ := x.call("POST", "/v1/auth/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`); code != 401 {
		t.Errorf("the tenant verify endpoint redeemed an operator challenge: %d", code)
	}
	code, done := x.call("POST", "/v1/operator/2fa/verify", "", `{"challenge":"`+half+`","code":"`+x.nextCode()+`"}`)
	if code != 200 || done["token"] == nil {
		t.Fatalf("operator verify → %d %v", code, done)
	}
	if code, _ := x.call("GET", "/v1/operator/queue", done["token"].(string), ""); code != 200 {
		t.Errorf("the redeemed operator session does not work: %d", code)
	}
}

func TestOperatorTwoFactor_ReplayAndAttemptCap(t *testing.T) {
	x := newOpTFA(t, false)
	x.opEnable()
	c := x.nextCode()
	half := x.opLogin()["challenge"].(string)
	if code, _ := x.call("POST", "/v1/operator/2fa/verify", "", `{"challenge":"`+half+`","code":"`+c+`"}`); code != 200 {
		t.Fatalf("first use → %d", code)
	}
	half = x.opLogin()["challenge"].(string)
	if code, _ := x.call("POST", "/v1/operator/2fa/verify", "", `{"challenge":"`+half+`","code":"`+c+`"}`); code != 401 {
		t.Errorf("an operator code worked twice: %d", code)
	}
	half = x.opLogin()["challenge"].(string) // a fresh challenge: the replay above already counted against the last one
	var last map[string]any
	for i := 0; i < maxMFAAttempts; i++ {
		_, last = x.call("POST", "/v1/operator/2fa/verify", "", `{"challenge":"`+half+`","code":"000000"}`)
	}
	if last["code"] != "two_factor_locked" {
		t.Errorf("after %d wrong codes: %v, want two_factor_locked", maxMFAAttempts, last)
	}
}

func TestOperatorTwoFactor_EnableSignsOutOtherSessionsButNotTheCaller(t *testing.T) {
	x := newOpTFA(t, false)
	other := x.opLogin()["token"].(string)
	tok := x.opEnable()
	if code, _ := x.call("GET", "/v1/operator/me", other, ""); code != 401 {
		t.Errorf("an operator session from before 2FA still works: %d", code)
	}
	if code, _ := x.call("GET", "/v1/operator/me", tok, ""); code != 200 {
		t.Errorf("the operator who turned 2FA on was signed out: %d", code)
	}
}

func TestOperatorTwoFactor_SeedSealedAndNotLeaked(t *testing.T) {
	x := newOpTFA(t, false)
	tok := x.opEnable()
	op, _ := x.st.GetOperator(context.Background(), "op-1")
	if op.TOTPSecretRef == "" || strings.Contains(op.TOTPSecretRef, x.sec) {
		t.Errorf("the operator seed is stored in plaintext: %q", op.TOTPSecretRef)
	}
	_, me := x.call("GET", "/v1/operator/me", tok, "")
	for k := range me {
		if strings.Contains(k, "totp") || strings.Contains(k, "recovery_hashes") {
			t.Errorf("/v1/operator/me exposes %q", k)
		}
	}
	if me["two_factor_enabled"] != true {
		t.Errorf("/v1/operator/me does not report two-factor on: %v", me)
	}
}

// With the deployment requiring it, an un-enrolled operator can enrol and nothing else.
func TestOperatorTwoFactor_DeploymentPolicyGatesClientWork(t *testing.T) {
	x := newOpTFA(t, true)
	tok := x.opLogin()["token"].(string)
	code, out := x.call("GET", "/v1/operator/queue", tok, "")
	if code != http.StatusForbidden || out["code"] != "two_factor_setup_required" {
		t.Fatalf("un-enrolled operator reached the client queue under the policy: %d %v", code, out)
	}
	if code, _ := x.call("POST", "/v1/operator/tenants/t1/risks/r1/decision", tok, `{"treatment":"accept"}`); code != http.StatusForbidden {
		t.Errorf("un-enrolled operator reached an act-on-behalf endpoint under the policy: %d", code)
	}
	if code, _ := x.call("GET", "/v1/operator/me", tok, ""); code != 200 {
		t.Errorf("an un-enrolled operator cannot see who they are under the policy: %d", code)
	}
	if code, _ := x.call("POST", "/v1/operator/2fa/setup", tok, `{"password":"correct-horse-1"}`); code != 200 {
		t.Errorf("an un-enrolled operator cannot enrol under the policy: %d", code)
	}
	// After enrolling, the policy no longer refuses — and it will not let the operator turn 2FA off.
	tok = x.opEnable()
	if code, _ := x.call("GET", "/v1/operator/queue", tok, ""); code != 200 {
		t.Errorf("an enrolled operator is still refused: %d", code)
	}
	code, out = x.call("POST", "/v1/operator/2fa/disable", tok, `{"password":"correct-horse-1","code":"`+x.nextCode()+`"}`)
	if code != http.StatusForbidden || out["code"] != "two_factor_required_by_policy" {
		t.Errorf("an operator turned 2FA off under a policy that requires it: %d %v", code, out)
	}
}

func TestOperatorTwoFactor_DisableNeedsBothFactorsWithoutPolicy(t *testing.T) {
	x := newOpTFA(t, false)
	tok := x.opEnable()
	if code, _ := x.call("POST", "/v1/operator/2fa/disable", tok, `{"password":"correct-horse-1"}`); code != 401 {
		t.Errorf("operator disable without a code → %d, want 401", code)
	}
	if code, _ := x.call("POST", "/v1/operator/2fa/disable", tok, `{"password":"correct-horse-1","code":"`+x.nextCode()+`"}`); code != 200 {
		t.Fatalf("operator disable with both → %d", code)
	}
	if l := x.opLogin(); l["token"] == nil {
		t.Error("after turning 2FA off, the password alone still does not sign in")
	}
}
