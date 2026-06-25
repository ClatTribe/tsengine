package webauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// authServer simulates a login: POST /login with the right password sets a session cookie;
// GET /me returns "Sign out" only when the cookie is present (else a login page).
func authServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("password") == "correct" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil && c.Value == "abc" {
			_, _ = w.Write([]byte(`<a href="/logout">Sign out</a>`))
			return
		}
		_, _ = w.Write([]byte(`<form><input type="password"></form> Please sign in`))
	})
	return httptest.NewServer(mux)
}

func TestReplayer_Login_ValidSession(t *testing.T) {
	srv := authServer()
	defer srv.Close()
	flow := LoginFlow{
		Type:          AuthRecorded,
		Steps:         []Step{{Method: "POST", URL: srv.URL + "/login", Fields: map[string]string{"password": "correct"}}},
		ValidateURL:   srv.URL + "/me",
		SuccessMarker: "Sign out",
		FailureMarker: "Please sign in",
	}
	s, err := NewReplayer().Login(context.Background(), flow)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !s.Valid {
		t.Error("a correct login + a Sign-out marker on /me should validate the session")
	}
	if len(s.Cookies) == 0 {
		t.Error("the session cookie should be captured for threading into the scan")
	}
}

func TestReplayer_Login_BadCreds_NotValid(t *testing.T) {
	srv := authServer()
	defer srv.Close()
	flow := LoginFlow{
		Type:          AuthRecorded,
		Steps:         []Step{{Method: "POST", URL: srv.URL + "/login", Fields: map[string]string{"password": "WRONG"}}},
		ValidateURL:   srv.URL + "/me",
		SuccessMarker: "Sign out",
		FailureMarker: "Please sign in",
	}
	s, _ := NewReplayer().Login(context.Background(), flow)
	if s.Valid {
		t.Error("a failed login must NOT validate (the FN guard: don't scan logged-out)")
	}
}

func TestReplayer_TokenFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer t" {
			_, _ = w.Write([]byte("welcome Sign out"))
			return
		}
		w.WriteHeader(401)
	}))
	defer srv.Close()
	flow := LoginFlow{Type: AuthToken, Token: "Bearer t", ValidateURL: srv.URL + "/", SuccessMarker: "Sign out"}
	s, err := NewReplayer().Login(context.Background(), flow)
	if err != nil || !s.Valid {
		t.Errorf("a token flow should validate via the Authorization header, got valid=%v err=%v", s.Valid, err)
	}
	if s.Headers["Authorization"] != "Bearer t" {
		t.Errorf("token flow should carry the auth header, got %v", s.Headers)
	}
}
