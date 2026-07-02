package webagent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// requireBrowser probes ONCE whether a real headless render works here (Chrome present). Tests that
// need a browser skip cleanly where none is available, so `go test ./...` stays green in CI.
var (
	browserProbeOnce sync.Once
	browserOK        bool
)

func requireBrowser(t *testing.T) {
	t.Helper()
	browserProbeOnce.Do(func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "<html><body>ok</body></html>")
		}))
		defer srv.Close()
		_, err := renderPage(context.Background(), srv.URL, 200*time.Millisecond)
		browserOK = err == nil
	})
	if !browserOK {
		t.Skip("headless browser unavailable here — skipping browser integration test")
	}
}

// TestBrowserRender_DetectsDOMXSS is the core proof: a page whose reflected param lands in a <script>
// sink and calls alert() must be detected as js_executed — the real-DOM execution signal that
// reflected-source matching cannot give. Skips where no Chrome is available.
func TestBrowserRender_DetectsDOMXSS(t *testing.T) {
	requireBrowser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q") // reflected UNESCAPED into a script context → executes in a browser
		fmt.Fprintf(w, "<html><body><div id=x></div><script>%s</script></body></html>", q)
	}))
	defer srv.Close()

	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 5, 0)
	cc.ctx = context.Background()
	out := tBrowserRender(cc, map[string]any{"url": srv.URL + "/?q=" + url.QueryEscape("alert(document.domain)")})
	if !strings.Contains(out, "js_executed") {
		t.Fatalf("DOM-XSS execution not detected:\n%s", out)
	}
	last := cc.History[len(cc.History)-1]
	if !hasIndicator(last, "js_executed") {
		t.Errorf("browser Turn missing the js_executed indicator: %+v", last.Indicators)
	}
	// grounding wiring: js_executed must satisfy a dom_xss finding
	if requiredIndicator["dom_xss"] != "js_executed" {
		t.Errorf("dom_xss is not grounded by js_executed")
	}
}

// TestBrowserRender_NoDialogOnBenign: a benign page fires no dialog → no false js_executed (the FP guard).
func TestBrowserRender_NoDialogOnBenign(t *testing.T) {
	requireBrowser(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><body><h1>hello world</h1></body></html>")
	}))
	defer srv.Close()
	cc := &Context{Target: srv.URL}
	cc.req = NewRequester([]string{hostOf(srv.URL)}, 5, 0)
	cc.ctx = context.Background()
	if out := tBrowserRender(cc, map[string]any{"url": srv.URL}); strings.Contains(out, "js_executed") {
		t.Errorf("benign page falsely reported js_executed:\n%s", out)
	}
}

// TestBrowserRender_AllowlistGate: an off-scope URL is blocked WITHOUT launching a browser (the scope
// guard runs first, so this needs no Chrome).
func TestBrowserRender_AllowlistGate(t *testing.T) {
	cc := &Context{Target: "http://good.example"}
	cc.req = NewRequester([]string{"good.example"}, 5, 0)
	cc.ctx = context.Background()
	if out := tBrowserRender(cc, map[string]any{"url": "http://evil.example/x"}); !strings.Contains(out, "OUT OF SCOPE") {
		t.Errorf("off-scope render not blocked: %s", out)
	}
	if out := tBrowserRender(cc, map[string]any{}); !strings.Contains(out, "url is required") {
		t.Errorf("missing-url not handled: %s", out)
	}
}
