package platformapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// addMember provisions a second seat in the tfa workspace and returns a session token for it.
func (x *tfa) addMember(email string) string {
	x.t.Helper()
	hash, _ := authn.HashPassword("member-horse-1")
	_ = x.st.PutUser(context.Background(), platform.User{ID: "u-" + email, TenantID: "t1", Email: email, Role: platform.RoleMember, PasswordHash: hash})
	code, out := x.call("POST", "/v1/auth/login", "", `{"email":"`+email+`","password":"member-horse-1"}`)
	if code != 200 || out["token"] == nil {
		x.t.Fatalf("member login → %d %v", code, out)
	}
	return out["token"].(string)
}

// The owner cannot require what they have not done themselves.
func TestTwoFactorPolicy_OwnerMustBeEnrolledFirst(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	tok := x.login()["token"].(string)
	code, out := x.call("PUT", "/v1/settings/security", tok, `{"require_two_factor":true}`)
	if code != http.StatusConflict || out["code"] != "owner_two_factor_off" {
		t.Fatalf("an owner without two-factor switched the policy on: %d %v", code, out)
	}
	ten, _ := x.st.GetTenant(context.Background(), "t1")
	if ten.RequireTwoFactor {
		t.Fatal("the refused request still changed the policy")
	}
}

// THE property: with the policy on, a seat without a second factor can enrol and do nothing else.
func TestTwoFactorPolicy_GatesUnenrolledSeatsToEnrolment(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	member := x.addMember("bo@acme.example")
	owner, _ := x.enable()

	code, out := x.call("PUT", "/v1/settings/security", owner, `{"require_two_factor":true}`)
	if code != 200 || out["require_two_factor"] != true {
		t.Fatalf("enabling the policy → %d %v", code, out)
	}
	// Who it gates is reported by name, so the owner can tell them.
	names, _ := out["without_two_factor"].([]any)
	if len(names) != 1 || names[0] != "bo@acme.example" {
		t.Errorf("the policy response does not name who it gates: %v", out["without_two_factor"])
	}
	for _, p := range []struct{ method, path string }{{"GET", "/v1/findings"}, {"GET", "/v1/issues"}, {"POST", "/v1/rescan"}} {
		code, out := x.call(p.method, p.path, member, `{}`)
		if code != http.StatusForbidden || out["code"] != "two_factor_setup_required" {
			t.Errorf("%s %s for an un-enrolled member under the policy → %d %v", p.method, p.path, code, out)
		}
	}
	// Enrolment stays reachable — or the policy locks people out instead of moving them in.
	code, me := x.call("GET", "/v1/auth/me", member, "")
	if code != 200 || me["two_factor_required"] != true {
		t.Errorf("/me under the policy → %d %v; it must stay reachable and report the policy", code, me)
	}
	if code, _ := x.call("POST", "/v1/auth/2fa/setup", member, `{"password":"member-horse-1"}`); code != 200 {
		t.Errorf("an un-enrolled member cannot enrol under the policy: %d", code)
	}
	// The owner, who has it, is not gated.
	if code, _ := x.call("GET", "/v1/findings", owner, ""); code != 200 {
		t.Errorf("the enrolled owner was refused under their own policy: %d", code)
	}
}

func TestTwoFactorPolicy_CannotTurnOwnOffWhileRequired(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	owner, _ := x.enable()
	if code, _ := x.call("PUT", "/v1/settings/security", owner, `{"require_two_factor":true}`); code != 200 {
		t.Fatalf("enabling the policy → %d", code)
	}
	code, out := x.call("POST", "/v1/auth/2fa/disable", owner, `{"password":"correct-horse-1","code":"`+x.nextCode()+`"}`)
	if code != http.StatusForbidden || out["code"] != "two_factor_required_by_policy" {
		t.Errorf("two-factor was turned off under a policy that requires it: %d %v", code, out)
	}
}

// A member may not weaken how the workspace signs in (the settings prefix is owner-only).
func TestTwoFactorPolicy_MemberCannotChangeIt(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	member := x.addMember("bo@acme.example")
	if code, _ := x.call("PUT", "/v1/settings/security", member, `{"require_two_factor":false}`); code != http.StatusForbidden {
		t.Errorf("a member changed the workspace's two-factor policy: %d", code)
	}
}

// Machine credentials are out of scope: the policy is about people.
func TestTwoFactorPolicy_DoesNotGateThePlatformToken(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	ten, _ := x.st.GetTenant(context.Background(), "t1")
	ten.RequireTwoFactor = true
	_ = x.st.PutTenant(context.Background(), ten)
	if rec := do(x.h, "GET", "/v1/findings", "t1", ""); rec.Code != 200 {
		t.Errorf("the platform token was gated by a person's sign-in policy: %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// tenantErrStore fails GetTenant, as a store blip would.
type tenantErrStore struct{ store.Store }

func (tenantErrStore) GetTenant(context.Context, string) (platform.Tenant, error) {
	return platform.Tenant{}, context.DeadlineExceeded
}

// Fail closed on doubt: when the workspace cannot be read, a seat WITHOUT a second factor is refused
// rather than let through a policy the owner may have set. A seat that has one is unaffected.
func TestTwoFactorPolicy_FailsClosedWhenTheWorkspaceCannotBeRead(t *testing.T) {
	x := newTFA(t, store.NewMemory(), vaultForTest(t))
	d := Deps{Store: tenantErrStore{x.st}}
	r := (&http.Request{}).WithContext(context.Background())
	if !d.twoFactorBlocks(r, "t1", platform.User{ID: "u"}) {
		t.Error("an unreadable workspace let a password-only seat through the two-factor policy")
	}
	if d.twoFactorBlocks(r, "t1", platform.User{ID: "u", TwoFactorEnabled: true}) {
		t.Error("a seat WITH two-factor was refused because the workspace could not be read")
	}
}
