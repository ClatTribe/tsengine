package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/authn"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type scimEnv struct {
	st    *store.Memory
	mux   http.Handler
	token string
}

func newSCIMEnv(t *testing.T, role string) scimEnv {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutUser(ctx, platform.User{ID: "owner", TenantID: "t1", Email: "cto@acme.com", Role: platform.RoleOwner})
	d := Deps{Store: st, PublicURL: "https://api.example"}
	mux := http.NewServeMux()
	for _, r := range []struct {
		pat string
		h   http.HandlerFunc
	}{
		{"GET /scim/v2/Users", d.scimAuth(d.handleSCIMListUsers)},
		{"POST /scim/v2/Users", d.scimAuth(d.handleSCIMCreateUser)},
		{"GET /scim/v2/Users/{id}", d.scimAuth(d.handleSCIMGetUser)},
		{"PUT /scim/v2/Users/{id}", d.scimAuth(d.handleSCIMReplaceUser)},
		{"PATCH /scim/v2/Users/{id}", d.scimAuth(d.handleSCIMPatchUser)},
		{"DELETE /scim/v2/Users/{id}", d.scimAuth(d.handleSCIMDeleteUser)},
	} {
		mux.HandleFunc(r.pat, r.h)
	}
	rec := httptest.NewRecorder()
	d.handleMintSCIMToken(rec, httptest.NewRequest(http.MethodPost, "/v1/settings/scim/token",
		strings.NewReader(`{"default_role":"`+role+`"}`)), "t1")
	var v scimSettingsView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != http.StatusOK || v.Token == "" {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body)
	}
	return scimEnv{st: st, mux: mux, token: v.Token}
}

func (e scimEnv) call(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.token)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// The lifecycle an identity provider drives: assign → a seat appears in the default role; unassign → the
// seat is DISABLED (kept, never deleted) and every session it held stops working; reassign → it returns.
func TestSCIM_ProvisionDeactivateReactivate(t *testing.T) {
	ctx := context.Background()
	e := newSCIMEnv(t, "employee")

	code, u := e.call(t, "POST", "/scim/v2/Users", `{"schemas":["`+scimUserSchema+`"],"userName":"Dev@Acme.com",
		"name":{"givenName":"Dev","familyName":"One"},"externalId":"okta-1","active":true}`)
	if code != http.StatusCreated || u["userName"] != "dev@acme.com" || u["active"] != true {
		t.Fatalf("create: %d %v", code, u)
	}
	id, _ := u["id"].(string)
	seat, _ := e.st.GetUser(ctx, id)
	if seat.Role != platform.RoleEmployee || seat.ProvisionedBy != "scim" || seat.Name != "Dev One" {
		t.Errorf("provisioned seat: %+v", seat)
	}

	// The person has a session; deactivation must end it AND make any survivor useless.
	_ = e.st.PutSession(ctx, platform.Session{Token: "sess-1", UserID: id, TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	code, u = e.call(t, "PATCH", "/scim/v2/Users/"+id,
		`{"schemas":["`+scimPatchSchema+`"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if code != http.StatusOK || u["active"] != false {
		t.Fatalf("deactivate (Entra's string form): %d %v", code, u)
	}
	if _, err := e.st.GetSession(ctx, "sess-1"); err == nil {
		t.Error("deactivation must end the seat's sessions")
	}
	_ = e.st.PutSession(ctx, platform.Session{Token: "sess-2", UserID: id, TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer sess-2")
	if _, ok := (Deps{Store: e.st}).resolveSession(req); ok {
		t.Error("a session belonging to a deactivated seat must authenticate nothing")
	}
	if s, _ := e.st.GetUser(ctx, id); !s.Disabled || s.DisabledBy != "scim" || s.Email == "" {
		t.Errorf("the seat must be kept and marked disabled: %+v", s)
	}

	code, u = e.call(t, "PATCH", "/scim/v2/Users/"+id,
		`{"Operations":[{"op":"replace","value":{"active":true}}]}`)
	if code != http.StatusOK || u["active"] != true {
		t.Fatalf("reactivate (Okta's value-object form): %d %v", code, u)
	}

	// DELETE deactivates; the seat is still there afterwards.
	if code, _ := e.call(t, "DELETE", "/scim/v2/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if s, err := e.st.GetUser(ctx, id); err != nil || !s.Disabled {
		t.Errorf("DELETE must deactivate, not remove: %+v %v", s, err)
	}
}

// The refusals, each of which would otherwise act on the wrong account or lock the workspace out.
func TestSCIM_Refusals(t *testing.T) {
	e := newSCIMEnv(t, "member")

	// An unsupported filter is refused, never answered with everyone.
	if code, out := e.call(t, "GET", `/scim/v2/Users?filter=emails.value+co+"acme"`, ""); code != http.StatusBadRequest || out["scimType"] != "invalidFilter" {
		t.Errorf("unsupported filter: %d %v", code, out)
	}
	// A supported filter returns exactly the match (and nothing when there is none).
	if code, out := e.call(t, "GET", `/scim/v2/Users?filter=userName+eq+"CTO@acme.com"`, ""); code != 200 || out["totalResults"] != float64(1) {
		t.Errorf("userName filter: %d %v", code, out)
	}
	if _, out := e.call(t, "GET", `/scim/v2/Users?filter=userName+eq+"nobody@acme.com"`, ""); out["totalResults"] != float64(0) {
		t.Errorf("a non-matching filter must return no one: %v", out)
	}
	// The owner cannot be deactivated by a directory change.
	if code, out := e.call(t, "PATCH", "/scim/v2/Users/owner", `{"Operations":[{"op":"replace","path":"active","value":false}]}`); code != http.StatusConflict {
		t.Errorf("owner deactivation must be refused: %d %v", code, out)
	}
	if code, _ := e.call(t, "DELETE", "/scim/v2/Users/owner", ""); code != http.StatusConflict {
		t.Errorf("owner DELETE must be refused: %d", code)
	}
	// A second seat for the same email is a conflict, not a duplicate.
	if code, out := e.call(t, "POST", "/scim/v2/Users", `{"userName":"cto@acme.com"}`); code != http.StatusConflict || out["scimType"] != "uniqueness" {
		t.Errorf("duplicate: %d %v", code, out)
	}
	// The email is the sign-in identity; renaming it would move a seat and everything it signed.
	if code, out := e.call(t, "PUT", "/scim/v2/Users/owner", `{"userName":"someone-else@acme.com"}`); code != http.StatusBadRequest || out["scimType"] != "mutability" {
		t.Errorf("rename: %d %v", code, out)
	}
}

// The token is the workspace's: a wrong one, another workspace's, and a revoked one are all refused, and
// provisioning never mints an owner.
func TestSCIM_TokenAndRoleGuards(t *testing.T) {
	e := newSCIMEnv(t, "member")
	ctx := context.Background()

	bad := e
	bad.token = e.token[:len(e.token)-2] + "00"
	if code, _ := bad.call(t, "GET", "/scim/v2/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("a tampered token must be refused: %d", code)
	}
	// Another workspace's id with this token's secret is refused (the digest is per workspace).
	_ = e.st.PutTenant(ctx, platform.Tenant{ID: "t2", SCIM: &platform.SCIMConfig{TokenHash: "x"}})
	other := e
	other.token = strings.Replace(e.token, "t1.", "t2.", 1)
	if code, _ := other.call(t, "GET", "/scim/v2/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("a token re-pointed at another workspace must be refused: %d", code)
	}

	d := Deps{Store: e.st}
	rec := httptest.NewRecorder()
	d.handleMintSCIMToken(rec, httptest.NewRequest("POST", "/v1/settings/scim/token", strings.NewReader(`{"default_role":"owner"}`)), "t1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("provisioning must never create owners: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	d.handleRevokeSCIM(rec, httptest.NewRequest("DELETE", "/v1/settings/scim", nil), "t1")
	if code, _ := e.call(t, "GET", "/scim/v2/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("a revoked token must be refused: %d", code)
	}
	// The settings view and the tenant's public view never carry the digest.
	tn, _ := e.st.GetTenant(ctx, "t1")
	tn.SCIM = &platform.SCIMConfig{TokenHash: "secret-digest"}
	if b, _ := json.Marshal(tn.Redacted()); strings.Contains(string(b), "secret-digest") {
		t.Error("Tenant.Redacted must drop the provisioning token digest")
	}
}

// Sign-in is refused for a deactivated seat with a message that says why — only after the password is
// right, so the message tells a guesser nothing.
func TestLogin_DeactivatedSeatIsRefused(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	h, _ := authn.HashPassword("correct horse battery")
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "dev@acme.com", Role: platform.RoleMember,
		PasswordHash: h, Disabled: true, DisabledBy: "scim"})
	d := Deps{Store: st}
	login := func(pw string) (int, string) {
		rec := httptest.NewRecorder()
		d.handleLogin(rec, httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"dev@acme.com","password":"`+pw+`"}`)))
		return rec.Code, rec.Body.String()
	}
	if code, body := login("wrong"); code != http.StatusUnauthorized || strings.Contains(body, "deactivated") {
		t.Errorf("a wrong password must not reveal the account state: %d %s", code, body)
	}
	if code, body := login("correct horse battery"); code != http.StatusForbidden || !strings.Contains(body, "account_disabled") {
		t.Errorf("a deactivated seat must be refused with the reason: %d %s", code, body)
	}
}
