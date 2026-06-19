// Command platform is the multi-tenant server for the autonomous security team
// (docs/autonomous-team.md). It wires the store + connectors + the engine
// (EngineRunner over a per-asset sandbox) + the HITL desk + remediation + GRC behind
// the platformapi HTTP surface AND the human-facing console (/ui), running the full
// loop: onboard → connect → scan → propose → gate → record compliance, every decision
// signed into the ledger. The console makes that loop clickable end to end: sign in →
// connect a system (OAuth) → posture dashboard → approve/reject fixes → compliance
// report.
//
// Durability today: a file-backed store (TSENGINE_PLATFORM_DB; else in-memory) and
// AES-256-GCM token sealing (TSENGINE_SECRET_KEY). A sqlite/Postgres store + a cloud-KMS
// vault are the scale-out successors behind the same interfaces. Set
// TSENGINE_PLATFORM_NO_ENGINE=1 to boot without the sandbox engine (connect / list /
// webhook-accept / operate-workspace only).
//
// Env:
//
//	TSENGINE_PLATFORM_TOKEN     static platform bearer token (required)
//	TSENGINE_PLATFORM_DB        path to a JSON store file (persists across restarts; else in-memory)
//	TSENGINE_PLATFORM_ADDR      listen address (default :8090)
//	TSENGINE_PLATFORM_PUBLIC    public base URL for OAuth redirect_uri
//	TSENGINE_SANDBOX_IMAGE      sandbox image ref (default tsengine/sandbox:latest)
//	TSENGINE_PLATFORM_NO_ENGINE 1 → boot without the sandbox engine
//	TSENGINE_MONITOR_INTERVAL  continuous re-scan cadence (e.g. 6h; default 12h; 0 disables)
//	TSENGINE_SLACK_WEBHOOK      Slack Incoming Webhook for approval notifications
//	TSENGINE_SLACK_SIGNING_SECRET  verifies Slack approve/reject button callbacks
//	PAGERDUTY_ROUTING_KEY      PagerDuty Events API v2 key — pages on-call for new high/critical incidents
//	GITHUB_CLIENT_ID/SECRET     GitHub OAuth app credentials
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/assetregistry"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/console"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/notify"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/platformapi"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/scheduler"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// newID returns a collision-resistant random id (48 bits of entropy, hex-encoded). A
// monotonic counter would reset to 0 on every restart and, against the persistent file
// store, silently overwrite existing tenants/users — a data-loss + isolation hazard now
// that self-serve signup creates tenants at runtime. Random ids never collide across
// restarts. The atomic counter remains a never-taken fallback if the RNG ever errors.
var seq uint64

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", atomic.AddUint64(&seq, 1))
	}
	return hex.EncodeToString(b[:])
}

func main() {
	token := os.Getenv("TSENGINE_PLATFORM_TOKEN")
	if token == "" {
		log.Fatal("TSENGINE_PLATFORM_TOKEN is required")
	}
	addr := envOr("TSENGINE_PLATFORM_ADDR", ":8090")
	image := envOr("TSENGINE_SANDBOX_IMAGE", "tsengine/sandbox:latest")

	st := openStore()
	reg := connector.NewRegistry(
		connector.NewGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),
		connector.NewGitLab(os.Getenv("GITLAB_CLIENT_ID"), os.Getenv("GITLAB_CLIENT_SECRET")),
		connector.NewGWorkspace(os.Getenv("GWORKSPACE_CLIENT_ID"), os.Getenv("GWORKSPACE_CLIENT_SECRET")),
		connector.NewM365(os.Getenv("M365_CLIENT_ID"), os.Getenv("M365_CLIENT_SECRET")),
		connector.NewOkta(os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_CLIENT_ID"), os.Getenv("OKTA_CLIENT_SECRET")),
		connector.NewAWS(os.Getenv("AWS_CFN_TEMPLATE_URL"), os.Getenv("AWS_TRUST_ACCOUNT_ID"), os.Getenv("AWS_REGION")),
	)
	vault, encrypted, verr := secret.FromEnv()
	if verr != nil {
		log.Fatalf("[platform] secret vault: %v", verr)
	}
	if encrypted {
		log.Print("[platform] OAuth tokens encrypted at rest (AES-256-GCM)")
	} else {
		log.Print("[platform] WARNING: tokens stored unsealed — set TSENGINE_SECRET_KEY (base64 32 bytes)")
	}
	tokens := secret.Tokens{V: vault}

	// the HITL desk delivers approved fixes through the connector write path, and
	// (optionally) pings Slack when a tier-gated action queues for approval.
	deliverer := &remediate.Deliverer{Store: st, Connectors: reg, Tokens: tokens}
	if base := os.Getenv("JIRA_BASE_URL"); base != "" {
		deliverer.Ticket = connector.NewJira(base, os.Getenv("JIRA_EMAIL"), os.Getenv("JIRA_API_TOKEN"), os.Getenv("JIRA_PROJECT"))
		log.Print("[platform] Jira ticket delivery enabled")
	} else if inst := os.Getenv("SERVICENOW_INSTANCE_URL"); inst != "" {
		deliverer.Ticket = connector.NewServiceNow(inst, os.Getenv("SERVICENOW_USER"), os.Getenv("SERVICENOW_PASSWORD"))
		log.Print("[platform] ServiceNow ticket delivery enabled")
	}
	desk := &hitl.Desk{Store: st, Apply: deliverer, Recorder: ledger.NewRecorder()}
	// new-incident alerts fan out to every configured channel (Slack heads-up +
	// PagerDuty on-call page); best-effort, so one failing never blocks the others.
	var alerters notify.MultiAlerter
	if hook := os.Getenv("TSENGINE_SLACK_WEBHOOK"); hook != "" {
		slack := notify.NewSlack(hook)
		desk.Notify = slack                // tier-gated approvals → Slack with buttons
		alerters = append(alerters, slack) // new incidents → Slack heads-up
		log.Print("[platform] Slack approval + incident notifications enabled")
	}
	if rk := os.Getenv("PAGERDUTY_ROUTING_KEY"); rk != "" {
		alerters = append(alerters, notify.NewPagerDuty(rk)) // new high/critical → on-call page
		log.Print("[platform] PagerDuty on-call paging enabled (high/critical)")
	}
	var incidentAlerter detect.Alerter
	if len(alerters) > 0 {
		incidentAlerter = alerters
	}
	if os.Getenv("TSENGINE_WEBHOOK_SECRET") == "" {
		log.Print("[platform] WARNING: inbound webhooks are NOT verified — set TSENGINE_WEBHOOK_SECRET to reject spoofed events")
	}
	g := &grc.GRC{Store: st}

	svc := &runner.Service{
		Store: st, Connectors: reg, Tokens: tokens, NewID: newID,
		GRC: g, Desk: desk,
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			return remediate.Propose(f, a, newID)
		},
		WebhookSecret: os.Getenv("TSENGINE_WEBHOOK_SECRET"), PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"),
		// continuous-monitoring: open/resolve incidents from change between passes,
		// alerting a human the moment a new at/above-threshold issue appears.
		Detector: &detect.Detector{Store: st, Recorder: ledger.NewRecorder(), Alerter: incidentAlerter, NewID: newID},
	}
	// The operate backend serves non-tech "workspace" assets (identity/email posture):
	// a snapshot file if the asset names one, else a LIVE fetch from the connected
	// Google Workspace directory. The sandbox engine serves tech assets. The mux routes
	// by type so one platform serves both audiences on the same store/grc/hitl/ledger loop.
	workspaceSource := runner.CompositeSource{
		Snapshot: runner.SnapshotSource{},
		Live: &runner.LiveWorkspaceSource{Store: st, Tokens: tokens, Fetchers: map[string]runner.Fetcher{
			platform.ConnGWorkspace: operate.NewGWorkspace(),
			platform.ConnM365:       operate.NewM365(),
			platform.ConnOkta:       operate.NewOkta(os.Getenv("OKTA_ORG_URL")),
		}, EmailAuth: operate.NewEmailAuth()},
	}
	workspaceRunner := &runner.OperateRunner{Source: workspaceSource, Apps: st}
	if os.Getenv("TSENGINE_PLATFORM_NO_ENGINE") != "1" {
		engine := &runner.EngineRunner{Resolve: assetregistry.HandlerFor, NewDispatcher: sandboxDispatcher(image)}
		svc.Scanner = &runner.MuxRunner{Engine: engine, Workspace: workspaceRunner}
	} else {
		log.Print("[platform] NO_ENGINE mode: tech-asset scanning disabled (operate workspace assets still run)")
		svc.Scanner = &runner.MuxRunner{Workspace: workspaceRunner}
	}

	api := platformapi.NewHandler(platformapi.Deps{
		Store: st, Connectors: reg, Runner: svc, Desk: desk, GRC: g, Vault: vault,
		Token: token, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"),
		SlackSigningSecret: os.Getenv("TSENGINE_SLACK_SIGNING_SECRET"),
		WebhookSecret:      os.Getenv("TSENGINE_WEBHOOK_SECRET"), NewID: newID,
	})
	// The human-facing dashboard (HTML) shares the same bearer token as the API (via a
	// browser session cookie) and drives the SAME gated desk for approvals. It falls
	// through to the API for every non-/ui path.
	ui := console.Handler(console.Deps{Store: st, Token: token, Desk: desk, Report: g,
		Connectors: reg, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"), Rescan: svc})
	mux := http.NewServeMux()
	mux.Handle("/ui", ui)
	mux.Handle("/ui/", ui)
	mux.Handle("/", api)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// continuous monitoring: re-scan every tenant on a cadence (the "autonomous" loop).
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	defer stopMonitor()
	sched := &scheduler.Scheduler{Store: st, Runner: svc, Interval: monitorInterval()}
	go func() { _ = sched.Run(monitorCtx) }()

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

// sandboxDispatcher returns a factory that spawns a per-asset sandbox and hands back
// the orchestrator Dispatcher + a teardown. Mirrors cmd/tsengine's scan path.
func sandboxDispatcher(image string) func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, func(), error) {
	return func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, func(), error) {
		opts := sandbox.SpawnOptions{Image: image}
		if types.AssetType(a.Type) == types.AssetCloudAccount {
			opts.Env = cloudCredentialEnv()
		}
		info, err := sandbox.Spawn(ctx, opts)
		if err != nil {
			return nil, nil, err
		}
		cleanup := func() { _ = sandbox.Destroy(context.Background(), info) }
		return sandbox.NewClient(info), cleanup, nil
	}
}

// cloudCredentialEnv forwards scoped, read-only cloud credentials into the sandbox
// (only the standard provider vars that are set in the platform's environment).
func cloudCredentialEnv() []string {
	var env []string
	for _, k := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION",
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
	} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// monitorInterval is the continuous re-scan cadence (TSENGINE_MONITOR_INTERVAL, e.g.
// "6h"). Default 12h; "0" disables the scheduler (event-driven re-scans only).
func monitorInterval() time.Duration {
	v := os.Getenv("TSENGINE_MONITOR_INTERVAL")
	if v == "" {
		return 12 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("[platform] bad TSENGINE_MONITOR_INTERVAL %q, using 12h", v)
		return 12 * time.Hour
	}
	return d
}

// openStore returns the file-backed store when TSENGINE_PLATFORM_DB points at a path
// (survives restarts), else an in-memory store.
func openStore() store.Store {
	if path := os.Getenv("TSENGINE_PLATFORM_DB"); path != "" {
		// A *.db / *.sqlite path → the durable SQLite store (ACID, indexed, the production
		// single-box backend). A *.json path → the legacy whole-snapshot file store.
		if ext := strings.ToLower(filepath.Ext(path)); ext == ".db" || ext == ".sqlite" || ext == ".sqlite3" {
			s, err := store.OpenSQLite(path)
			if err != nil {
				log.Fatalf("[platform] open sqlite store %s: %v", path, err)
			}
			log.Printf("[platform] sqlite store at %s", path)
			return s
		}
		f, err := store.OpenFile(path)
		if err != nil {
			log.Fatalf("[platform] open store %s: %v", path, err)
		}
		log.Printf("[platform] file store at %s", path)
		return f
	}
	log.Print("[platform] in-memory store (set TSENGINE_PLATFORM_DB=/data/platform.db to persist)")
	return store.NewMemory()
}
