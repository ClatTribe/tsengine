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

func TestIsLoginWall_JSONAuthError(t *testing.T) {
	f := LoginFlow{}
	// FN fixes: API/SPA auth walls returned as a JSON body (status alone wouldn't reveal these
	// — e.g. a 200 with a JSON error, which the old check missed).
	walls := []string{
		`{"error":"unauthorized"}`,
		`{"message":"Authentication required"}`,
		`{"code":"token_expired","message":"please re-login"}`,
		`{"error":"invalid_token"}`,
		`{"detail":"Authentication credentials were not provided."}`, // DRF
		`  {"title":"Unauthenticated"}  `,                            // leading space + title key
	}
	for _, body := range walls {
		if !IsLoginWall(200, "", body, f) {
			t.Errorf("a JSON auth-error body should be a login wall: %s", body)
		}
	}

	// FP guards: must NOT fire on...
	noFire := []string{
		`<html><body>The page returned 401 Unauthorized earlier. Read more.</body></html>`, // HTML mentioning the word
		`{"data":{"article":"how to handle unauthorized access in your API"}}`,             // JSON without an error key
		`{"status":"ok","user":"alice"}`,                                                   // a normal authed JSON response
		`{"error":"validation failed","field":"email"}`,                                    // a non-auth error
	}
	for _, body := range noFire {
		if IsLoginWall(200, "", body, f) {
			t.Errorf("must NOT flag as a login wall (FP): %s", body)
		}
	}
}

func TestAccuracy_LoginWallCorpus(t *testing.T) {
	s := ScoreLoginWall(LoginWallCorpus(), LoginFlow{})
	t.Logf("login-wall accuracy: recall=%.2f precision=%.2f (TP=%d FN=%d FP=%d TN=%d)",
		s.Recall(), s.Precision(), s.TP, s.FN, s.FP, s.TN)

	// The bar: every real login wall is detected (recall 1.0 — incl. the #325 JSON paths) and no
	// normal authenticated response is mistaken for one (precision 1.0 — the FP guards).
	if s.Recall() != 1.0 {
		t.Errorf("login-wall recall must be 1.0, got %.2f (FN=%d)", s.Recall(), s.FN)
	}
	if s.Precision() != 1.0 {
		t.Errorf("login-wall precision must be 1.0, got %.2f (FP=%d)", s.Precision(), s.FP)
	}
}
