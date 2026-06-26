package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// exchConn returns a raw token from Exchange (the transient form the callback seals).
type exchConn struct{ fakeConn }

func (exchConn) Exchange(context.Context, string, string) (platform.Connection, error) {
	return platform.Connection{Kind: platform.ConnGitHub, Status: platform.ConnActive, SecretRef: "ghp_RAWTOKEN"}, nil
}

// recordingSealer wraps a raw token so we can prove the stored ref isn't the plaintext.
type recordingSealer struct{ sealed []string }

func (s *recordingSealer) Seal(p string) (string, error) {
	s.sealed = append(s.sealed, p)
	return "enc:OPAQUE-CIPHERTEXT", nil // a real vault never embeds the plaintext
}

func (s *recordingSealer) Open(string) (string, error) { return "", nil }

func TestConnectCallback_SealsTokenBeforePersist(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	sealer := &recordingSealer{}
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: reg, Runner: svc, Vault: sealer, Token: "tok", PublicURL: "https://app"})

	// OAuth callback: code + state(tenant). (No bearer auth — it's the OAuth redirect.)
	req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc&state=t1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("callback: code %d body %s", rec.Code, rec.Body.String())
	}

	// the raw token must have been sealed...
	if len(sealer.sealed) != 1 || sealer.sealed[0] != "ghp_RAWTOKEN" {
		t.Fatalf("token not sealed: %v", sealer.sealed)
	}
	// ...and the PERSISTED connection must hold the sealed ref, never the plaintext
	conns, _ := st.ListConnections(context.Background(), "t1")
	if len(conns) != 1 {
		t.Fatalf("want 1 connection, got %d", len(conns))
	}
	if strings.Contains(conns[0].SecretRef, "ghp_RAWTOKEN") {
		t.Fatalf("SECURITY: the raw token was persisted: %q", conns[0].SecretRef)
	}
	if !strings.HasPrefix(conns[0].SecretRef, "enc:") {
		t.Errorf("stored ref should be sealed, got %q", conns[0].SecretRef)
	}
}

// With AppURL set, the OAuth callback must land the browser back IN THE APP (303 → /assets) instead of
// dumping a raw JSON blob — the post-connect "aha". Without AppURL it stays JSON (the test above).
func TestConnectCallback_RedirectsToAppWhenAppURLSet(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	sealer := &recordingSealer{}
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: fakeTokens{}, Scanner: fakeScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: reg, Runner: svc, Vault: sealer, Token: "tok", PublicURL: "https://app", AppURL: "https://app.example/"})

	req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc&state=t1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303 redirect, got %d body %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://app.example/assets?connected=github") {
		t.Fatalf("redirect should land on the app /assets with the connected kind, got %q", loc)
	}
	// the connection must still be persisted (sealed) — the redirect is on top of, not instead of, the work
	if conns, _ := st.ListConnections(context.Background(), "t1"); len(conns) != 1 {
		t.Fatalf("want 1 persisted connection, got %d", len(conns))
	}
}

func TestConnectCallback_MissingCodeOrState(t *testing.T) {
	st := store.NewMemory()
	reg := connector.NewRegistry(exchConn{})
	h := NewHandler(Deps{Store: st, Connectors: reg, Token: "tok"})
	req := httptest.NewRequest("GET", "/v1/connect/github/callback?code=abc", nil) // no state
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing state should be 400, got %d", rec.Code)
	}
}
