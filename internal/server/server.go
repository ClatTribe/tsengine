// Package server is the long-running tsengine HTTP service — the deployable
// surface webappsec talks to (CLAUDE.md §9). It mounts the tool-replay API behind
// bearer-token auth, exposes liveness/readiness/version probes for orchestrators
// (k8s, Fly, ECS), logs every request, and shuts down gracefully on SIGTERM.
//
// The handler is split from the listener (Handler vs Run) so the whole routing +
// auth + logging stack is unit-testable with httptest, no port binding.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ClatTribe/tsengine/internal/replay"
)

// Config bounds the service.
type Config struct {
	Addr    string // listen address, e.g. ":8080"
	Token   string // bearer token required for protected endpoints
	RunsDir string // where completed scans live (for /replay)
	Version string // reported by /version
}

// Handler builds the full routing stack (probes + authenticated /replay) wrapped
// in request logging. Exposed separately from Run for testing.
func Handler(cfg Config, spawner replay.Spawner) http.Handler {
	mux := http.NewServeMux()

	// Liveness: the process is up. No auth, no dependencies — k8s livenessProbe.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok")
	})

	// Readiness: the process can serve traffic (runs dir writable). k8s readinessProbe.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := checkReady(cfg.RunsDir); err != nil {
			writeText(w, http.StatusServiceUnavailable, "not ready: "+err.Error())
			return
		}
		writeText(w, http.StatusOK, "ready")
	})

	// Version: build identity. No auth (not sensitive); handy for deploy verification.
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": cfg.Version})
	})

	// The tool-replay API — the "dig deeper" surface (CLAUDE.md §9), behind auth.
	mux.Handle("/replay", requireToken(cfg.Token, replay.HTTPHandler(cfg.RunsDir, spawner)))

	// Root: a tiny human-readable index.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeText(w, http.StatusOK, "tsengine "+cfg.Version+"\nendpoints: GET /healthz /readyz /version, POST /replay (bearer auth)\n")
	})

	return logging(mux)
}

// Run starts the service and blocks until ctx is cancelled (SIGINT/SIGTERM),
// then drains in-flight requests with a timeout. A missing token is a hard error —
// the service refuses to expose /replay without auth.
func Run(ctx context.Context, cfg Config, spawner replay.Spawner) error {
	if cfg.Token == "" {
		return errors.New("server: an API token is required (set TSENGINE_API_TOKEN or --token) — refusing to serve /replay unauthenticated")
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           Handler(cfg, spawner),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Printf("[server] tsengine %s listening on %s", cfg.Version, cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Printf("[server] shutdown signal received, draining…")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}

// requireToken is the bearer-auth middleware. Constant-time comparison; the token
// is never logged. Missing/blank server token denies everything (defense in depth —
// Run already refuses to start without one).
func requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := bearer(r.Header.Get("Authorization"))
		if token == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

// logging records method, path, status, size and latency for every request.
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("[server] %s %s %d %dB %s", r.Method, r.URL.Path, sw.status, sw.bytes, time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusWriter) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }
func (s *statusWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// checkReady verifies the runs dir is usable (created if absent, write-probed).
func checkReady(runsDir string) error {
	if runsDir == "" {
		return errors.New("no runs dir configured")
	}
	if err := os.MkdirAll(runsDir, 0o750); err != nil {
		return err
	}
	probe := filepath.Join(runsDir, ".readyz")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return err
	}
	_ = os.Remove(probe)
	return nil
}

func writeText(w http.ResponseWriter, code int, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(s)))
	w.WriteHeader(code)
	_, _ = w.Write([]byte(s))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
