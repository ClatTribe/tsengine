package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDefaultCreds_NoFalsePositiveOnRotatingRedirect: a login that redirects EVERY failed POST back to
// the login page with a fresh per-request token in the QUERY (?error=1&csrf=<nonce> — the common
// PRG-on-failure + CSRF/flash pattern) must NOT be read as a login success. The single-baseline
// differential compared the FULL Location string, so a rotating query token made every default pair
// look like "a redirect the baseline didn't get" — a false-positive flood (the #813 dynamic-baseline
// class). NO pair is accepted here, so the correct answer is zero hits.
func TestDefaultCreds_NoFalsePositiveOnRotatingRedirect(t *testing.T) {
	var n int
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		n++ // every attempt fails, but each redirect carries a fresh token in the query
		w.Header().Set("Location", fmt.Sprintf("/login?error=1&csrf=%d%s", n, randHex(6)))
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	out := tDefaultCreds(cc, map[string]any{"url": srv.URL + "/login"})
	if strings.Contains(out, "DEFAULT CREDENTIALS WORK") {
		t.Errorf("false positive — a rotating-token failure redirect was read as a login success:\n%s", out)
	}
}

// TestDefaultCreds_NoFalsePositiveOnUniformSessionCookie: a login that sets a fresh-VALUE session
// cookie (same name) on EVERY POST including failures must not be read as a success. Name-based
// comparison already handles this; this pins it so a future change can't regress it.
func TestDefaultCreds_NoFalsePositiveOnUniformSessionCookie(t *testing.T) {
	var n int
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		n++
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: fmt.Sprintf("v%d%s", n, randHex(6)), Path: "/"})
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>invalid</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 40, 0)
	cc.ctx = context.Background()

	out := tDefaultCreds(cc, map[string]any{"url": srv.URL + "/login"})
	if strings.Contains(out, "DEFAULT CREDENTIALS WORK") {
		t.Errorf("false positive — a uniformly-set session cookie was read as a login success:\n%s", out)
	}
}
