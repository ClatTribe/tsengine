package apiauthz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPProber_SendsIdentityHeadersAndReadsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the caller's identity so the test can prove the headers were sent.
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"caller":"` + r.Header.Get("Authorization") + `"}`))
	}))
	defer srv.Close()

	p := NewHTTPProber()
	resp, err := p.Do(context.Background(), Request{Method: "GET", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer victim"}})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	if !strings.Contains(resp.Body, "Bearer victim") {
		t.Errorf("the identity's Authorization header should reach the server, got %q", resp.Body)
	}
}

func TestHTTPProber_BodyCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()
	p := &HTTPProber{Client: http.DefaultClient, MaxBody: 100}
	resp, _ := p.Do(context.Background(), Request{URL: srv.URL})
	if len(resp.Body) != 100 {
		t.Errorf("body should be capped at 100 bytes, got %d", len(resp.Body))
	}
}

func TestLiveProber_Gated(t *testing.T) {
	t.Setenv("TSENGINE_ACTIVE_EXPLOIT", "")
	if LiveProber() != nil {
		t.Error("without the active-exploit flag, no live prober (active testing must be opt-in)")
	}
	t.Setenv("TSENGINE_ACTIVE_EXPLOIT", "1")
	if LiveProber() == nil {
		t.Error("with the flag set, a live prober should be returned")
	}
}
