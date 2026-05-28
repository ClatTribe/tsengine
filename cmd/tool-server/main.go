// Command tool-server is the sandbox-side HTTP API. It runs as PID 1
// inside the strix-sandbox docker image and exposes:
//
//	GET  /healthz   → 200 OK + version JSON
//	POST /execute   → dispatches a registered Tool by name
//
// Auth: every request to /execute must carry Authorization: Bearer
// <token>, matching TSENGINE_AUTH_TOKEN from the environment.
//
// Tools are registered via init() in their wrapper packages — see the
// imports.go file in this directory for the blank-import list. Adding a
// tool means importing its package; no central wiring is needed.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// Version is shipped in the /healthz body for sanity checks.
var Version = "0.1.0-dev"

func main() {
	addr := flag.String("addr", envOr("TSENGINE_ADDR", ":8080"), "listen address")
	flag.Parse()

	token := strings.TrimSpace(os.Getenv("TSENGINE_AUTH_TOKEN"))
	if token == "" {
		fmt.Fprintln(os.Stderr, "tool-server: TSENGINE_AUTH_TOKEN must be set")
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/corpus", requireBearer(token, handleCorpus))
	mux.HandleFunc("/execute", requireBearer(token, handleExecute))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		fmt.Fprintf(os.Stderr, "tool-server %s listening on %s; %d tools registered\n",
			Version, *addr, len(tool.All()))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "tool-server: %v\n", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"version":    Version,
		"tool_count": len(tool.All()),
	})
}

func handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req sandbox.ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "decode request: "+err.Error())
		return
	}
	if req.Tool == "" {
		writeErr(w, http.StatusBadRequest, "missing tool name")
		return
	}
	t, ok := tool.Get(req.Tool)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("unknown tool %q", req.Tool))
		return
	}
	result, err := t.Run(r.Context(), req.Args)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tool run: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// requireBearer enforces the Authorization: Bearer <token> header via a
// constant-time comparison.
func requireBearer(expected string, next http.HandlerFunc) http.HandlerFunc {
	expectedHeader := "Bearer " + expected
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(expectedHeader)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
