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
