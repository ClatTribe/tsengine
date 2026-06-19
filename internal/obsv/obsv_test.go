package obsv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// the middleware must pass requests through unchanged (status + body) while recording
// metrics, and the /metrics endpoint must then expose the request counter.
func TestMiddlewarePassesThroughAndRecords(t *testing.T) {
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewed"))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if rec.Body.String() != "brewed" {
		t.Fatalf("body = %q, want brewed", rec.Body.String())
	}

	// the request we just served must appear in the Prometheus exposition.
	mrec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(mrec.Body)
	if !strings.Contains(string(body), `tsengine_http_requests_total{code="418",method="GET"}`) {
		t.Fatalf("metrics missing the request counter; got:\n%s", body)
	}
}

// the recorder must preserve http.Flusher so the SSE stream (/v1/events) still flushes.
func TestRecorderIsFlusher(t *testing.T) {
	var flushed bool
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("wrapped ResponseWriter is not an http.Flusher")
		}
		_, _ = w.Write([]byte("event: ping\n\n"))
		f.Flush()
		flushed = true
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/events", nil))
	if !flushed {
		t.Fatal("handler never reached the flush path")
	}
}

// RegisterScanJobsInflight must publish a gauge that reflects the snapshot function.
func TestScanJobsInflightGauge(t *testing.T) {
	RegisterScanJobsInflight(func() float64 { return 3 })
	mrec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(mrec.Body)
	if !strings.Contains(string(body), "tsengine_scan_jobs_inflight 3") {
		t.Fatalf("metrics missing scan_jobs_inflight gauge; got:\n%s", body)
	}
}
