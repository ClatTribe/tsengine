package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// loginServer is a fake login endpoint: the one good pair (goodUser/goodPass) redirects to /dashboard
// and sets a session cookie; everything else re-renders the form with "invalid" (200, no redirect).
func loginServer(t *testing.T, goodUser, goodPass string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("username") == goodUser && r.PostFormValue("password") == goodPass {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authed-" + goodUser, Path: "/"})
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>invalid credentials</body></html>")
	})
	return httptest.NewServer(mux)
}

// TestDefaultCreds_FindsWorkingPair: a login that accepts admin/admin is detected via the redirect
// differential vs the failed baseline, and the winning turn carries the default_creds indicator.
func TestDefaultCreds_FindsWorkingPair(t *testing.T) {
	srv := loginServer(t, "admin", "admin")
	defer srv.Close()
	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	out := tDefaultCreds(cc, map[string]any{"url": srv.URL + "/login"})
	if !strings.Contains(out, "DEFAULT CREDENTIALS WORK") || !strings.Contains(out, "admin:admin") {
		t.Fatalf("working default pair not reported:\n%s", out)
	}
	last := cc.History[len(cc.History)-1]
	if !hasIndicator(last, "default_creds") {
		t.Errorf("winning turn missing the default_creds indicator: %+v", last.Indicators)
	}
	if !contains(requiredIndicator["default_credentials"], "default_creds") {
		t.Errorf("default_credentials class not grounded by default_creds")
	}
}

// TestDefaultCreds_NoFalsePositive: a login that rejects EVERY pair the same way (200 + "invalid")
// yields no hit — the FP guard (§10). No default pair is in this server's allowed set.
func TestDefaultCreds_NoFalsePositive(t *testing.T) {
	srv := loginServer(t, "realuser", "Sup3rSecret!") // not in defaultCreds
	defer srv.Close()
	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	out := tDefaultCreds(cc, map[string]any{"url": srv.URL + "/login"})
	if strings.Contains(out, "DEFAULT CREDENTIALS WORK") {
		t.Errorf("false positive — reported a working pair against a login that rejects all defaults:\n%s", out)
	}
	if !strings.Contains(out, "no default credentials worked") {
		t.Errorf("expected the no-hit message: %s", out)
	}
}

// TestDefaultCreds_RequiresURL: missing url is a graceful error.
func TestDefaultCreds_RequiresURL(t *testing.T) {
	if out := tDefaultCreds(&Context{}, map[string]any{}); !strings.Contains(out, "url is required") {
		t.Errorf("missing-url not handled: %s", out)
	}
}
