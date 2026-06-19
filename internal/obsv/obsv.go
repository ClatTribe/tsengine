// Package obsv is the platform's observability-lite layer: structured logging (slog) and
// a Prometheus /metrics endpoint. No external infrastructure is required to start — a
// single box runs the server and a local Prometheus (or `curl /metrics`) reads it; the
// logs go to stderr as text (dev) or JSON (prod). It sits behind a thin surface so a
// richer stack (OTel traces, a push gateway) can replace it later without touching call
// sites.
//
// What it exposes:
//   - tsengine_http_requests_total{method,code}      — request counts (low-cardinality)
//   - tsengine_http_request_duration_seconds{method} — latency histogram
//   - tsengine_scan_jobs_inflight                    — queued+running background scans
//   - the standard Go runtime collectors (goroutines, heap, GC) — the signals you watch
//     to catch a leak on a long-running single box, for free via the default registry.
package obsv

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpReqs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tsengine_http_requests_total",
		Help: "Total HTTP requests handled, by method and response code.",
	}, []string{"method", "code"})

	httpDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tsengine_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})
)

func init() {
	prometheus.MustRegister(httpReqs, httpDur)
}

// SetupLogging installs a structured slog handler as the default logger. Format is text
// by default (readable in a terminal) or JSON when TSENGINE_LOG_FORMAT=json (parseable by
// a log pipeline); level is info by default or TSENGINE_LOG_LEVEL (debug/info/warn/error).
// Existing log.Print calls still go to stderr — this adds structured logging alongside
// them, it does not rip them out.
func SetupLogging() {
	opts := &slog.HandlerOptions{Level: logLevel()}
	var h slog.Handler
	if strings.EqualFold(os.Getenv("TSENGINE_LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("TSENGINE_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// MetricsHandler is the Prometheus /metrics endpoint (default registry → includes the Go
// runtime + process collectors plus the metrics registered here).
func MetricsHandler() http.Handler { return promhttp.Handler() }

// RegisterScanJobsInflight publishes the count of queued+running background scans as a
// gauge. The caller passes a snapshot function (e.g. the jobs.Pool's Inflight) so this
// package stays decoupled from the jobs package. Safe to call once at startup.
func RegisterScanJobsInflight(count func() float64) {
	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tsengine_scan_jobs_inflight",
		Help: "Background scan jobs currently queued or running.",
	}, count))
}

// Middleware records a request's count + latency and emits a structured access log. It is
// the outermost wrapper around the platform mux. Metrics labels stay low-cardinality
// (method + status code, never the raw path — ids in the path would explode the series
// count); the full path rides only in the log line, where cardinality is free.
//
// The long-lived SSE stream (/v1/events) is logged but excluded from the latency
// histogram: its "duration" is the client's connection lifetime (minutes), which would
// skew the buckets. /metrics and /healthz are served but not logged, to keep scrape +
// health-check noise out of the log.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/metrics" || path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &respRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start)

		httpReqs.WithLabelValues(r.Method, strconv.Itoa(rec.status)).Inc()
		if path != "/v1/events" { // exclude the long-lived SSE stream from the latency histogram
			httpDur.WithLabelValues(r.Method).Observe(dur.Seconds())
		}
		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelWarn
		}
		slog.LogAttrs(r.Context(), level, "http_request",
			slog.String("method", r.Method),
			slog.String("path", path),
			slog.Int("status", rec.status),
			slog.Int64("dur_ms", dur.Milliseconds()),
		)
	})
}

// respRecorder captures the response status for metrics/logging while delegating the
// http.Flusher the SSE handler relies on (without Flush, /v1/events would buffer and
// never stream).
type respRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *respRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *respRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func (r *respRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
