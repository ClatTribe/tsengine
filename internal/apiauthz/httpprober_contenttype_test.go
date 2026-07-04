package apiauthz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPProber_DefaultsJSONContentTypeForBody: the mass_assignment write sends a JSON body (e.g.
// {"name":"me","role":"admin"}) carrying only the attacker's AUTH headers — no Content-Type. Many APIs
// do request.json() / body-parsing middleware and silently ignore (or 500 on) a body with no parseable
// Content-Type, so the privileged field never gets set, the read-back is clean, and a REAL
// mass-assignment vuln is missed — a false negative. The prober must default the Content-Type from the
// body shape (the same fix the webagent shipped for the XBEN-006 opaque-500 dead end).
func TestHTTPProber_DefaultsJSONContentTypeForBody(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &HTTPProber{Client: srv.Client(), MaxBody: 1 << 10}
	_, err := p.Do(context.Background(), Request{
		Method: "POST", URL: srv.URL, Body: `{"name":"me","role":"admin"}`,
		Headers: map[string]string{"Authorization": "Bearer attacker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" {
		t.Errorf("JSON body sent without application/json Content-Type (got %q) — a request.json() API drops the mass_assignment write", gotCT)
	}
}

// TestHTTPProber_RespectsExplicitContentType: an explicit Content-Type in the identity headers is not
// overwritten by the default.
func TestHTTPProber_RespectsExplicitContentType(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &HTTPProber{Client: srv.Client(), MaxBody: 1 << 10}
	_, err := p.Do(context.Background(), Request{
		Method: "POST", URL: srv.URL, Body: `<xml/>`,
		Headers: map[string]string{"Content-Type": "application/xml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/xml" {
		t.Errorf("explicit Content-Type overwritten (got %q, want application/xml)", gotCT)
	}
}

// TestHTTPProber_SendsAuthHeader: a regression guard — the per-identity auth header MUST reach the
// server, or the BOLA/BFLA differential is invalid (both requests would be unauth).
func TestHTTPProber_SendsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &HTTPProber{Client: srv.Client(), MaxBody: 1 << 10}
	_, err := p.Do(context.Background(), Request{
		Method: "GET", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer victim-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer victim-token" {
		t.Errorf("auth header dropped (got %q) — the BOLA/BFLA differential would be invalid", gotAuth)
	}
}
