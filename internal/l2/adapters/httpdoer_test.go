package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDoer_GetReflectsAndRendersStatusHeadersBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Echo a header + the query so a reflected-payload check can confirm.
		_, _ = w.Write([]byte("echo=" + r.URL.RawQuery + " ua=" + r.Header.Get("X-Probe")))
	}))
	defer srv.Close()

	d := NewHTTPDoer()
	out, err := d.Do(context.Background(), "GET", srv.URL+"?q=<script>alert(1)</script>",
		map[string]string{"X-Probe": "tsengine"}, "")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	for _, want := range []string{"HTTP 200", "Content-Type: text/html", "alert(1)", "ua=tsengine"} {
		if !strings.Contains(out, want) {
			t.Errorf("response summary missing %q in:\n%s", want, out)
		}
	}
}

func TestHTTPDoer_RejectsNonHTTPScheme(t *testing.T) {
	d := NewHTTPDoer()
	if _, err := d.Do(context.Background(), "GET", "file:///etc/passwd", nil, ""); err == nil {
		t.Error("non-http(s) scheme must be rejected (verification primitive, not arbitrary I/O)")
	}
	if _, err := d.Do(context.Background(), "GET", "://broken", nil, ""); err == nil {
		t.Error("an unparseable URL should error")
	}
}

func TestHTTPDoer_CapsBodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("A", 200<<10))) // 200 KiB
	}))
	defer srv.Close()

	d := NewHTTPDoer()
	out, err := d.Do(context.Background(), "GET", srv.URL, nil, "")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Body read is capped at defaultMaxBody (64 KiB), not the full 200 KiB.
	if n := strings.Count(out, "A"); n > int(defaultMaxBody)+1024 {
		t.Errorf("body read should be capped near %d bytes, saw %d 'A's", defaultMaxBody, n)
	}
}
