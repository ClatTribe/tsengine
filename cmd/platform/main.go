// Command platform is the multi-tenant API server for the autonomous security team
// (docs/autonomous-team.md). It wires the store + connectors + runner behind the
// platformapi HTTP surface. For the MVP the store is in-memory and the GitHub
// connector is configured from env; sqlite/Postgres + a secret vault + the web
// dashboard land in later phases.
//
// Env:
//
//	TSENGINE_PLATFORM_TOKEN   static platform bearer token (required)
//	TSENGINE_PLATFORM_ADDR    listen address (default :8090)
//	GITHUB_CLIENT_ID/SECRET   GitHub OAuth app credentials (optional for boot)
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/platformapi"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// envTokens is the MVP secret resolver: connections vault their token inline as
// "vault:<token>" (Exchange's transient form). A real KMS-envelope vault replaces
// this behind the runner.Tokens interface.
type envTokens struct{}

func (envTokens) Resolve(_ context.Context, c platform.Connection) (string, error) {
	const p = "vault:"
	if len(c.SecretRef) > len(p) && c.SecretRef[:len(p)] == p {
		return c.SecretRef[len(p):], nil
	}
	return "", errors.New("platform: no token for connection")
}

func main() {
	token := os.Getenv("TSENGINE_PLATFORM_TOKEN")
	if token == "" {
		log.Fatal("TSENGINE_PLATFORM_TOKEN is required")
	}
	addr := os.Getenv("TSENGINE_PLATFORM_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	st := store.NewMemory()
	reg := connector.NewRegistry(
		connector.NewGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),
	)
	// NOTE: Scanner is nil here — wiring the real EngineRunner (sandbox dispatcher)
	// is the next step; the API surface (connect/list/webhook-accept) boots without it.
	svc := &runner.Service{Store: st, Connectors: reg, Tokens: envTokens{}}

	h := platformapi.NewHandler(platformapi.Deps{Store: st, Connectors: reg, Runner: svc, Token: token})
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		log.Printf("[platform] listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[platform] serve: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Print("[platform] draining…")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}
