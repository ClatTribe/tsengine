package webauth

import "testing"

func TestValidateSession(t *testing.T) {
	f := LoginFlow{SuccessMarker: "Sign out", FailureMarker: "Invalid credentials"}

	// 2xx with the success marker → authenticated.
	if !ValidateSession(200, `<a href="/logout">Sign out</a>`, f) {
		t.Error("a 2xx page showing 'Sign out' should validate as authenticated")
	}
	// 2xx but showing the failure marker (a login page returned 200) → NOT authenticated.
	if ValidateSession(200, `<form>Invalid credentials</form>`, f) {
		t.Error("a 200 login/error page is not a valid session")
	}
	// 2xx without the success marker → not confirmed.
	if ValidateSession(200, `<h1>Welcome</h1>`, f) {
		t.Error("with a success marker configured, its absence means not authenticated")
	}
	// Non-2xx → never authenticated.
	if ValidateSession(302, "Sign out", f) {
		t.Error("a redirect is never a validated session")
	}
	// No markers configured → best-effort: 2xx is accepted.
	if !ValidateSession(200, "anything", LoginFlow{}) {
		t.Error("no markers → a 2xx should be accepted (best-effort)")
	}
}

func TestIsLoginWall(t *testing.T) {
	f := LoginFlow{FailureMarker: "Please sign in"}

	cases := []struct {
		name     string
		status   int
		location string
		body     string
		want     bool
	}{
		{"401", 401, "", "", true},
		{"403", 403, "", "", true},
		{"redirect to login", 302, "https://app/login?next=/x", "", true},
		{"redirect to sso", 302, "/sso/authorize", "", true},
		{"redirect elsewhere", 302, "/dashboard", "", false},
		{"failure marker inline", 200, "", "<div>Please sign in</div>", true},
		{"password form inline", 200, "", `<input type="password" name="pw">`, true},
		{"authenticated page", 200, "", "<h1>Your invoices</h1>", false},
	}
	for _, c := range cases {
		if got := IsLoginWall(c.status, c.location, c.body, f); got != c.want {
			t.Errorf("%s: IsLoginWall = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPlanAndAuthHeaders(t *testing.T) {
	// Token flow: no steps, an Authorization header.
	tok := LoginFlow{Type: AuthToken, Token: "Bearer abc"}
	if len(tok.Plan()) != 0 {
		t.Error("a token flow has no replay steps")
	}
	if tok.AuthHeaders()["Authorization"] != "Bearer abc" {
		t.Errorf("token flow should carry the Authorization header, got %v", tok.AuthHeaders())
	}
	// Recorded flow: the ordered steps are the plan; no auth header (session is in the cookie).
	rec := LoginFlow{Type: AuthRecorded, Steps: []Step{{Method: "GET", URL: "/login"}, {Method: "POST", URL: "/login"}}}
	if len(rec.Plan()) != 2 {
		t.Errorf("a recorded flow should replay its steps, got %d", len(rec.Plan()))
	}
	if rec.AuthHeaders() != nil {
		t.Error("a cookie/recorded flow carries no auth header")
	}
}
