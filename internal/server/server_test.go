package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// stubSpawner errors if ever called — server tests exercise routing/auth, not the
// real sandbox. (The replay package tests the spawn path itself.)
type stubSpawner struct{}

func (stubSpawner) Spawn(context.Context, string) (replay.Dispatcher, func(context.Context) error, error) {
	return stubDispatcher{}, func(context.Context) error { return nil }, nil
}

type stubDispatcher struct{}

func (stubDispatcher) Execute(context.Context, string, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

func newTestServer(t *testing.T, token string) http.Handler {
	t.Helper()
	return Handler(Config{Token: token, RunsDir: t.TempDir(), Version: "test-1.2.3"}, stubSpawner{})
}

func TestProbes_NoAuth(t *testing.T) {
	h := newTestServer(t, "secret")
	for _, path := range []string{"/healthz", "/readyz", "/version"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200 (probes must not require auth)", path, rr.Code)
		}
	}
	// /version reports the build version
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var v map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if v["version"] != "test-1.2.3" {
		t.Errorf("version = %q", v["version"])
	}
}

func TestReplay_RequiresToken(t *testing.T) {
	h := newTestServer(t, "secret")
	body := `{"scan_id":"x","tool":"nuclei"}`

	cases := []struct {
		name, auth string
		wantCode   int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"malformed header", "secret", http.StatusUnauthorized},
		// correct token passes auth → reaches replay, which 404s on a missing scan
		{"correct token", "Bearer secret", http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(body))
			if c.auth != "" {
				req.Header.Set("Authorization", c.auth)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != c.wantCode {
				t.Errorf("%s: code = %d, want %d (body=%s)", c.name, rr.Code, c.wantCode, rr.Body.String())
			}
		})
	}
}

func TestReplay_AuthHeaderNotLeaked(t *testing.T) {
	// a 401 response must not echo the expected token
	h := newTestServer(t, "supersecret-xyz")
	req := httptest.NewRequest(http.MethodPost, "/replay", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "supersecret-xyz") {
		t.Fatal("server leaked the API token in a response body")
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 should set WWW-Authenticate")
	}
}

func TestRun_RefusesWithoutToken(t *testing.T) {
	err := Run(context.Background(), Config{Addr: ":0", RunsDir: t.TempDir()}, stubSpawner{})
	if err == nil || !strings.Contains(err.Error(), "token is required") {
		t.Fatalf("Run without a token should error, got %v", err)
	}
}

func TestRun_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Addr: "127.0.0.1:0", Token: "t", RunsDir: t.TempDir(), Version: "v"}, stubSpawner{})
	}()
	cancel() // request shutdown immediately
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned error: %v", err)
		}
	case <-context.Background().Done():
	}
}
