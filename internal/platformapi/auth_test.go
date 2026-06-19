package platformapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postJSON(h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getBearer(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuth_SignupLoginSessionFlow(t *testing.T) {
	h, _ := setup(t)

	// --- signup creates a workspace + owner and returns a session ---
	rec := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Globex","email":"ada@globex.io","password":"hunter2hunter2"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Fatalf("signup leaked the password hash: %s", rec.Body.String())
	}
	var s struct {
		Token  string `json:"token"`
		Tenant string `json:"tenant"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil || s.Token == "" || s.Tenant == "" {
		t.Fatalf("signup returned no session: %s", rec.Body.String())
	}

	// --- duplicate email (case-insensitive) is rejected ---
	if rec := postJSON(h, "/v1/auth/signup", "", `{"workspace":"X","email":"ADA@globex.io","password":"hunter2hunter2"}`); rec.Code != http.StatusConflict {
		t.Errorf("duplicate email: want 409, got %d", rec.Code)
	}

	// --- the session token authenticates a data endpoint, scoped to the new tenant ---
	if rec := getBearer(h, "/v1/findings", s.Token); rec.Code != http.StatusOK {
		t.Errorf("session on /v1/findings: want 200, got %d", rec.Code)
	}

	// --- /me returns the signed-in user, hash redacted ---
	rec = getBearer(h, "/v1/auth/me", s.Token)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ada@globex.io") {
		t.Fatalf("/me: want the user, got %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "pbkdf2") {
		t.Errorf("/me leaked the password hash")
	}

	// --- login: wrong password and unknown email both 401 with the same message ---
	bad := postJSON(h, "/v1/auth/login", "", `{"email":"ada@globex.io","password":"nope"}`)
	unknown := postJSON(h, "/v1/auth/login", "", `{"email":"nobody@x.io","password":"whatever1"}`)
	if bad.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized {
		t.Errorf("bad creds: want 401/401, got %d/%d", bad.Code, unknown.Code)
	}
	if bad.Body.String() != unknown.Body.String() {
		t.Errorf("login error messages differ (account enumeration): %q vs %q", bad.Body.String(), unknown.Body.String())
	}

	// --- login with correct password returns a fresh, working session ---
	rec = postJSON(h, "/v1/auth/login", "", `{"email":"ada@globex.io","password":"hunter2hunter2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// --- logout revokes the session ---
	if rec := postJSON(h, "/v1/auth/logout", s.Token, ""); rec.Code != http.StatusOK {
		t.Errorf("logout: want 200, got %d", rec.Code)
	}
	if rec := getBearer(h, "/v1/auth/me", s.Token); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout, /me: want 401, got %d", rec.Code)
	}
}

func TestAuth_TeamInvite(t *testing.T) {
	h, _ := setup(t)

	owner := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Initech","email":"boss@initech.com","password":"ownerpass1"}`)
	var o struct{ Token, Tenant string }
	_ = json.Unmarshal(owner.Body.Bytes(), &o)

	// owner invites a teammate → 201 with a one-time temp password
	inv := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"dev@initech.com","name":"Dev"}`)
	if inv.Code != http.StatusCreated {
		t.Fatalf("invite: want 201, got %d (%s)", inv.Code, inv.Body.String())
	}
	var ir struct {
		TempPassword string                `json:"temp_password"`
		User         struct{ Role string } `json:"user"`
	}
	_ = json.Unmarshal(inv.Body.Bytes(), &ir)
	if len(ir.TempPassword) < 8 || ir.User.Role != "member" {
		t.Fatalf("invite payload bad: %s", inv.Body.String())
	}

	// the teammate signs in with the temp password
	li := postJSON(h, "/v1/auth/login", "", `{"email":"dev@initech.com","password":"`+ir.TempPassword+`"}`)
	if li.Code != http.StatusOK {
		t.Fatalf("member login with temp password: want 200, got %d", li.Code)
	}

	// the team lists both members, hashes redacted
	team := getBearer(h, "/v1/auth/team", o.Token)
	if team.Code != http.StatusOK || !strings.Contains(team.Body.String(), "boss@initech.com") || !strings.Contains(team.Body.String(), "dev@initech.com") {
		t.Fatalf("team: want both members, got %d %s", team.Code, team.Body.String())
	}
	if strings.Contains(team.Body.String(), "pbkdf2") {
		t.Error("team leaked password hashes")
	}

	// a member cannot invite (owner-only)
	var member struct{ Token string }
	_ = json.Unmarshal(li.Body.Bytes(), &member)
	if rec := postJSON(h, "/v1/auth/invite", member.Token, `{"email":"x@initech.com"}`); rec.Code != http.StatusForbidden {
		t.Errorf("member invite: want 403, got %d", rec.Code)
	}
}

// TestAuth_ForcedPasswordRotation: an invited member must set their own password before
// the app unlocks — the owner-issued temp password can't be the standing credential.
func TestAuth_ForcedPasswordRotation(t *testing.T) {
	h, _ := setup(t)

	owner := postJSON(h, "/v1/auth/signup", "", `{"workspace":"Hooli","email":"gavin@hooli.com","password":"ownerpass1"}`)
	var o struct{ Token string }
	_ = json.Unmarshal(owner.Body.Bytes(), &o)

	inv := postJSON(h, "/v1/auth/invite", o.Token, `{"email":"dev@hooli.com","name":"Dev"}`)
	var ir struct {
		TempPassword string `json:"temp_password"`
	}
	_ = json.Unmarshal(inv.Body.Bytes(), &ir)

	// the member logs in with the temp password; the login response flags the forced change
	li := postJSON(h, "/v1/auth/login", "", `{"email":"dev@hooli.com","password":"`+ir.TempPassword+`"}`)
	if li.Code != http.StatusOK {
		t.Fatalf("member temp login: want 200, got %d", li.Code)
	}
	var ses struct {
		Token string `json:"token"`
		User  struct {
			MustChangePassword bool `json:"must_change_password"`
		} `json:"user"`
	}
	_ = json.Unmarshal(li.Body.Bytes(), &ses)
	if !ses.User.MustChangePassword {
		t.Fatalf("login should flag must_change_password for an invited member: %s", li.Body.String())
	}

	// app endpoints are BLOCKED with a machine-readable code until the password is set
	blocked := getBearer(h, "/v1/findings", ses.Token)
	if blocked.Code != http.StatusForbidden || !strings.Contains(blocked.Body.String(), "password_change_required") {
		t.Fatalf("app endpoint should be 403 password_change_required, got %d %s", blocked.Code, blocked.Body.String())
	}
	// …but the auth-management endpoints stay reachable so the user can fix it
	if rec := getBearer(h, "/v1/auth/me", ses.Token); rec.Code != http.StatusOK {
		t.Fatalf("/me must stay reachable during forced change, got %d", rec.Code)
	}

	// wrong current password is rejected
	if rec := postJSON(h, "/v1/auth/password", ses.Token, `{"current_password":"wrong","new_password":"brandnew99"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("change with wrong current: want 401, got %d", rec.Code)
	}
	// setting the new password clears the flag
	chg := postJSON(h, "/v1/auth/password", ses.Token, `{"current_password":"`+ir.TempPassword+`","new_password":"brandnew99"}`)
	if chg.Code != http.StatusOK {
		t.Fatalf("change password: want 200, got %d (%s)", chg.Code, chg.Body.String())
	}

	// the SAME session now unlocks the app
	if rec := getBearer(h, "/v1/findings", ses.Token); rec.Code != http.StatusOK {
		t.Errorf("after password change the app should unlock, got %d", rec.Code)
	}
	// the temp password no longer logs in; the new one does
	if rec := postJSON(h, "/v1/auth/login", "", `{"email":"dev@hooli.com","password":"`+ir.TempPassword+`"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("old temp password should no longer work, got %d", rec.Code)
	}
	if rec := postJSON(h, "/v1/auth/login", "", `{"email":"dev@hooli.com","password":"brandnew99"}`); rec.Code != http.StatusOK {
		t.Errorf("new password should log in, got %d", rec.Code)
	}
}

// TestAuth_SessionTenantIsolation asserts a session can only ever read its own tenant —
// the X-Tenant-ID header cannot override the tenant bound to the session.
func TestAuth_SessionTenantIsolation(t *testing.T) {
	h, _ := setup(t)

	a := postJSON(h, "/v1/auth/signup", "", `{"workspace":"A","email":"a@a.io","password":"passwordA1"}`)
	var sa struct {
		Token, Tenant string
	}
	_ = json.Unmarshal(a.Body.Bytes(), &sa)
	b := postJSON(h, "/v1/auth/signup", "", `{"workspace":"B","email":"b@b.io","password":"passwordB1"}`)
	var sb struct {
		Token, Tenant string
	}
	_ = json.Unmarshal(b.Body.Bytes(), &sb)
	if sa.Tenant == sb.Tenant || sa.Token == "" || sb.Token == "" {
		t.Fatalf("expected two distinct tenants/sessions, got %+v / %+v", sa, sb)
	}

	// User A, using their session but spoofing tenant B's id in the header, must still be
	// scoped to A (handler receives the session's tenant, not the header).
	req := httptest.NewRequest("GET", "/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+sa.Token)
	req.Header.Set("X-Tenant-ID", sb.Tenant)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "a@a.io") {
		t.Fatalf("session A with B's tenant header resolved to the wrong user: %s", rec.Body.String())
	}
}
