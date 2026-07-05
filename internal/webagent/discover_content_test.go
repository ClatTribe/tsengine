package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscoverContent_FindsHiddenPath: an unlinked page (/private.php) that returns 200 while missing
// paths 404 is found via the differential; a random path is not. Found paths join cc.Routes.
func TestDiscoverContent_FindsHiddenPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private.php" {
			fmt.Fprint(w, "<h1>Private Zone</h1>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 Not Found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 60, 0)
	cc.ctx = context.Background()
	out := tDiscoverContent(cc, map[string]any{})
	if !strings.Contains(out, "/private.php") {
		t.Fatalf("hidden path not discovered:\n%s", out)
	}
	if !containsStr(cc.Routes, srv.URL+"/private.php") {
		t.Errorf("discovered path not added to routes: %v", cc.Routes)
	}
}

// TestDiscoverContent_FindsHiddenParam: a page that only reacts to ?file= (echoes a not-found message)
// has `file` reported as a changing param; inert names are not (no false positive on a static page).
func TestDiscoverContent_FindsHiddenParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := r.URL.Query().Get("file"); f != "" {
			fmt.Fprintf(w, "<h1>Private</h1><p>File not exists or is not readable: %s</p>", f)
			return
		}
		fmt.Fprint(w, "<h1>Private</h1>") // no-param baseline
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 60, 0)
	cc.ctx = context.Background()
	out := tDiscoverContent(cc, map[string]any{"params_for": srv.URL + "/private.php"})
	if !strings.Contains(out, "file") {
		t.Fatalf("hidden param `file` not discovered:\n%s", out)
	}
}

// TestDiscoverContent_QuietWhenNothingHidden: a soft-404 server that returns the SAME page for every
// path yields no invented hits (§10 — grounded differential).
func TestDiscoverContent_QuietWhenNothingHidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<h1>Same page for everything</h1>") // identical for all paths
	}))
	defer srv.Close()
	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 60, 0)
	cc.ctx = context.Background()
	if out := tDiscoverContent(cc, map[string]any{}); strings.Contains(out, "DISCOVERED") {
		t.Errorf("invented hidden paths against a soft-404 server:\n%s", out)
	}
}

// TestDiscoverContent_FindsJSONAPIActionRoute: a modern JSON-API app (Flask/FastAPI/Express) hides its
// functional surface behind ACTION/verb routes (/healthcheck, /run, /render), NOT the PHP file names
// (login.php, admin.php) the old wordlist knew. Observed live on a real Flask-microservice benchmark
// (XBEN-082): discover_content probed 45 PHP-oriented paths, reported "no hidden paths found", and the
// agent never reached the eval/render sink — a recon blind spot for the whole JSON-API class. The
// wordlist must carry generic API/RPC/health action routes so this surface is discoverable. Uses
// /healthcheck (a generic service route, not a target-specific name — §14.2).
func TestDiscoverContent_FindsJSONAPIActionRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthcheck" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 Not Found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 200, 0)
	cc.ctx = context.Background()
	out := tDiscoverContent(cc, map[string]any{})
	if !strings.Contains(out, "/healthcheck") {
		t.Fatalf("JSON-API action route /healthcheck not discovered (wordlist is PHP/file-oriented, blind to API/action verbs):\n%s", out)
	}
}

// TestCommonPaths_CoversAPIActionRoutes: guards the wordlist itself — a purely PHP/file-oriented list
// (admin.php, login.php, backup.sql) is blind to the JSON-API/RPC class. Assert the highest-signal
// generic API/action/health route names are present so the regression that lost XBEN-082 can't recur.
func TestCommonPaths_CoversAPIActionRoutes(t *testing.T) {
	// Generic (non-SUT-specific, §14.2) API/RPC/health verbs a modern-app recon list must carry.
	want := []string{"healthcheck", "run", "exec", "render", "api", "graphql"}
	have := map[string]bool{}
	for _, p := range commonPaths {
		have[p] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("commonPaths is missing the generic API/action route %q — the JSON-API recon blind spot", w)
		}
	}
}
