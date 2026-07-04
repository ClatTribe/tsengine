package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscoverContent_NoFalsePositiveOnDynamicSoft404: a server that 200s EVERY path (soft-404) with a
// body whose SIZE varies per request (a rotating banner / variable-length nonce / path-derived "did you
// mean") must NOT yield invented path hits. The single-sample baseline + size-diff signal flags every
// probed path here — a false-positive flood that violates the tool's "no invented surface" promise
// (§10). A two-sample baseline calibration detects the unstable baseline and falls back to status-only.
func TestDiscoverContent_NoFalsePositiveOnDynamicSoft404(t *testing.T) {
	var n int
	// bodies of very different lengths, cycled per (sequential) request — a rotating banner
	banners := []string{"", strings.Repeat("A", 200), strings.Repeat("B", 20), strings.Repeat("C", 500)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b := banners[n%len(banners)]
		n++
		fmt.Fprintf(w, "<h1>Home</h1><div class=banner>%s</div>", b) // 200 for EVERY path, size varies
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 60, 0)
	cc.ctx = context.Background()
	if out := tDiscoverContent(cc, map[string]any{}); strings.Contains(out, "DISCOVERED") {
		t.Errorf("invented hidden paths against a DYNAMIC (size-varying) soft-404 server:\n%s", out)
	}
}

// TestDiscoverContent_NoFalseParamOnDynamicPage: a page whose body SIZE rotates per request but does NOT
// react to any specific query param must NOT have a param reported as "response changed". The
// paramSizeDiffers signal fires for every inert param on such a page; the calibration suppresses it.
func TestDiscoverContent_NoFalseParamOnDynamicPage(t *testing.T) {
	var n int
	sizes := []int{10, 300, 30, 600}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s := sizes[n%len(sizes)] // size rotates per request, independent of any query param
		n++
		fmt.Fprintf(w, "<h1>Page</h1>%s", strings.Repeat("x", s))
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 60, 0)
	cc.ctx = context.Background()
	out := tDiscoverContent(cc, map[string]any{"params_for": srv.URL + "/p"})
	if strings.Contains(out, "response changed") {
		t.Errorf("invented a changing param on a dynamic (param-independent) page:\n%s", out)
	}
}
