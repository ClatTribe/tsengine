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
//	TSENGINE_ACTIVE_EXPLOIT    1 → wire the live active-exploitation Prober (still
//	                           consent-gated per engagement; absent → passive only)
//	PAGERDUTY_ROUTING_KEY      PagerDuty Events API v2 key — pages on-call for new high/critical incidents
//	TSENGINE_TEAMS_WEBHOOK     Microsoft Teams Incoming Webhook — posts new high/critical incidents
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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/assetregistry"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/connector/awsremediate"
	"github.com/ClatTribe/tsengine/internal/connector/azremediate"
	"github.com/ClatTribe/tsengine/internal/connector/gcpremediate"
	"github.com/ClatTribe/tsengine/internal/console"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/notify"
	"github.com/ClatTribe/tsengine/internal/obsv"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/pentest"
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
	obsv.SetupLogging()  // structured logs (slog); set TSENGINE_LOG_FORMAT=json in prod
	hydrateFileSecrets() // Docker-secret *_FILE convention → load file-backed secrets into env
	token := os.Getenv("TSENGINE_PLATFORM_TOKEN")
	if token == "" {
		log.Fatal("TSENGINE_PLATFORM_TOKEN is required")
	}
	addr := envOr("TSENGINE_PLATFORM_ADDR", ":8090")
	image := envOr("TSENGINE_SANDBOX_IMAGE", "tsengine/sandbox:latest")

	st := openStore()
	// AWS: read-only onboarding + the live, reversible remediation write path. The S3 writer is
	// wired ONLY when a remediation role/creds are configured — else Apply stays the honest stub.
	// (S3 Block Public Access needs WRITE creds, distinct from the read-only onboarding role.)
	awsConn := connector.NewAWS(os.Getenv("AWS_CFN_TEMPLATE_URL"), os.Getenv("AWS_TRUST_ACCOUNT_ID"), os.Getenv("AWS_REGION"))
	if os.Getenv("AWS_REMEDIATION_ROLE_ARN") != "" || os.Getenv("AWS_REMEDIATION_ENABLED") == "1" {
		awsConn.Writer = awsremediate.NewS3Writer(os.Getenv("AWS_REGION"),
			os.Getenv("AWS_REMEDIATION_ROLE_ARN"), os.Getenv("AWS_REMEDIATION_EXTERNAL_ID"))
		log.Print("[platform] AWS live remediation enabled (S3 Block Public Access)")
	}
	// Per-tenant write path: each customer brings their OWN cross-account role (set via UX →
	// Connection.Config). The factory is just an SDK-free constructor (the STS assume-role + write
	// only fire at Apply, behind the HITL gate), so it's always wired.
	awsConn.WriterForConfig = func(region, roleARN string) connector.AWSWriter {
		return awsremediate.NewS3Writer(region, roleARN, "")
	}
	// GCP: read-only onboarding + the live, reversible remediation write path (GCS Public Access
	// Prevention). The writer is wired ONLY when remediation is configured — else Apply stays the
	// honest stub. The write impersonates a scoped SA, distinct from the read-only onboarding grant.
	gcpConn := connector.NewGCP(os.Getenv("GCP_TRUST_SERVICE_ACCOUNT"))
	if os.Getenv("GCP_REMEDIATION_IMPERSONATE_SA") != "" || os.Getenv("GCP_REMEDIATION_ENABLED") == "1" {
		gcpConn.Writer = gcpremediate.NewGCSWriter(os.Getenv("GCP_REMEDIATION_IMPERSONATE_SA"))
		log.Print("[platform] GCP live remediation enabled (GCS Public Access Prevention)")
	}
	gcpConn.WriterForConfig = func(sa string) connector.GCPWriter { return gcpremediate.NewGCSWriter(sa) }
	// Azure: read-only onboarding + the live remediation write path (disable storage public access).
	// The writer uses the platform's service-principal creds (DefaultAzureCredential), scoped to the
	// subscription on the connection. Wired only when remediation is enabled — else honest stub.
	azureConn := connector.NewAzure(os.Getenv("AZURE_TRUST_APP_ID"))
	if os.Getenv("AZURE_REMEDIATION_ENABLED") == "1" {
		azureConn.Writer = azremediate.NewStorageWriter()
		log.Print("[platform] Azure live remediation enabled (disable storage public access)")
	}
	azureConn.WriterForConfig = func() connector.AzureWriter { return azremediate.NewStorageWriter() }
	reg := connector.NewRegistry(
		connector.NewGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),
		connector.NewGitLab(os.Getenv("GITLAB_CLIENT_ID"), os.Getenv("GITLAB_CLIENT_SECRET")),
		connector.NewBitbucket(os.Getenv("BITBUCKET_CLIENT_ID"), os.Getenv("BITBUCKET_CLIENT_SECRET")),
		connector.NewAzureDevOps(os.Getenv("AZURE_DEVOPS_CLIENT_ID"), os.Getenv("AZURE_DEVOPS_CLIENT_SECRET"), os.Getenv("AZURE_DEVOPS_ORG")),
		connector.NewGWorkspace(os.Getenv("GWORKSPACE_CLIENT_ID"), os.Getenv("GWORKSPACE_CLIENT_SECRET")),
		connector.NewM365(os.Getenv("M365_CLIENT_ID"), os.Getenv("M365_CLIENT_SECRET")),
		connector.NewOkta(os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_CLIENT_ID"), os.Getenv("OKTA_CLIENT_SECRET")),
		awsConn,
		gcpConn,
		azureConn,
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
	} else if key := os.Getenv("LINEAR_API_KEY"); key != "" {
		deliverer.Ticket = connector.NewLinear(key, os.Getenv("LINEAR_TEAM_ID"))
		log.Print("[platform] Linear ticket delivery enabled")
	}
	// Per-tenant Jira routing (Bucket B): a file_ticket lands in the tenant's OWN Jira (sealed
	// config set via Settings → Jira), falling back to the operator tracker above. The resolver
	// opens the sealed token per ticket; a miss falls through. So ticketing is multi-tenant.
	deliverer.Ticket = remediate.TenantFiler{
		Resolve: func(ctx context.Context, tenantID string) (base, email, token, project string, ok bool) {
			t, gerr := st.GetTenant(ctx, tenantID)
			if gerr != nil || !t.Jira.HasToken() {
				return "", "", "", "", false
			}
			tok, oerr := vault.Open(t.Jira.TokenRef)
			if oerr != nil || tok == "" {
				return "", "", "", "", false
			}
			return t.Jira.BaseURL, t.Jira.Email, tok, t.Jira.Project, true
		},
		Fallback: deliverer.Ticket, // operator-global tracker (may be nil → no-destination no-op)
	}
	// One shared ledger recorder across the whole platform — the desk, the detector, AND the API's
	// HITL endpoints (risk decision / policy publish / audit attest / pentest sign-off) all sign into
	// the SAME ledger, so §18.2 inv. 4 ("every decision is signed") holds end to end. Previously the
	// API Deps had no recorder, so HITL acts served by the API were silently NOT ledgered.
	rec := ledger.NewRecorder()
	desk := &hitl.Desk{Store: st, Apply: deliverer, Recorder: rec}
	// new-incident alerts fan out to every configured channel (Slack heads-up +
	// PagerDuty on-call page); best-effort, so one failing never blocks the others.
	var alerters notify.MultiAlerter
	// channelMap is the channel-name → destination map the escalation PolicyRouter routes through
	// (so a policy tier "critical → pagerduty,slack" reaches the right channels). Populated only
	// with the channels the operator actually configured.
	channelMap := map[string]notify.Alerter{}
	if hook := os.Getenv("TSENGINE_SLACK_WEBHOOK"); hook != "" {
		slack := notify.NewSlack(hook)
		desk.Notify = slack                // tier-gated approvals → Slack with buttons
		alerters = append(alerters, slack) // new incidents → Slack heads-up
		channelMap["slack"] = slack
		log.Print("[platform] Slack approval + incident notifications enabled")
	}
	if rk := os.Getenv("PAGERDUTY_ROUTING_KEY"); rk != "" {
		pd := notify.NewPagerDuty(rk)
		alerters = append(alerters, pd) // new high/critical → on-call page
		channelMap["pagerduty"] = pd
		log.Print("[platform] PagerDuty on-call paging enabled (high/critical)")
	}
	if hook := os.Getenv("TSENGINE_TEAMS_WEBHOOK"); hook != "" {
		teams := notify.NewTeams(hook)
		alerters = append(alerters, teams) // new high/critical → Microsoft Teams heads-up
		channelMap["teams"] = teams
		log.Print("[platform] Microsoft Teams incident notifications enabled (high/critical)")
	}
	if hook := os.Getenv("TSENGINE_DISCORD_WEBHOOK"); hook != "" {
		disc := notify.NewDiscord(hook)
		alerters = append(alerters, disc) // new high/critical → Discord channel embed
		channelMap["discord"] = disc
		log.Print("[platform] Discord incident notifications enabled (high/critical)")
	}
	if url := os.Getenv("TSENGINE_WEBHOOK_URL"); url != "" {
		// The generic outbound webhook — a signed JSON event per new incident, so a tenant can
		// wire TensorShield into anything (Zapier/Make/n8n/SIEM/custom) without a bespoke connector.
		wh := notify.NewWebhook(url, os.Getenv("TSENGINE_WEBHOOK_SIGNING_SECRET"))
		alerters = append(alerters, wh)
		channelMap["webhook"] = wh
		log.Print("[platform] generic outbound webhook enabled (signed incident events)")
	}
	// Per-tenant Slack routing (Bucket B): each tenant's new-incident heads-up goes to its OWN
	// configured Slack webhook (sealed, set via Settings → Notifications), with the operator
	// MultiAlerter as the fallback. The resolver opens the sealed ref per incident; a miss falls
	// through to the operator channels. So incident notifications are multi-tenant, not one shared
	// channel. (Approval buttons stay the operator Slack app — those need its interactive endpoint.)
	tenantRouter := notify.TenantRouter{
		Resolve: func(ctx context.Context, tenantID string) (string, bool) {
			t, gerr := st.GetTenant(ctx, tenantID)
			if gerr != nil || !t.HasSlackWebhook() {
				return "", false
			}
			url, oerr := vault.Open(t.SlackWebhookRef)
			if oerr != nil || url == "" {
				return "", false
			}
			return url, true
		},
		Fallback: alerters, // operator-global channels (may be empty → fallback is a no-op)
	}
	// Escalation matrix (Phase 2): when a tenant has an enabled escalation policy, a new incident is
	// routed by severity to the channels named in the matching tier; otherwise it falls back to the
	// per-tenant Slack + operator channels (tenantRouter). So routing is policy-driven, not fixed.
	incidentAlerter := detect.Alerter(notify.PolicyRouter{
		Resolve: func(ctx context.Context, tenantID string) *platform.EscalationPolicy {
			t, gerr := st.GetTenant(ctx, tenantID)
			if gerr != nil {
				return nil
			}
			return t.Escalation
		},
		Channels: channelMap,
		Default:  tenantRouter,
	})
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
		// Bulk fix: group an asset's related alerts into one PR per fix unit (supersedes
		// the per-finding Propose above).
		ProposeBatch: func(fs []types.Finding, a platform.Asset) []platform.Action {
			return remediate.ProposeBulk(fs, a, newID)
		},
		// A-RSP: a newly-opened critical incident → a tier-2 gated containment runbook + a T3
		// breach-disclosure draft for a human to sign.
		ProposeIncidentResponse: func(inc platform.Incident) ([]platform.Action, bool) {
			return remediate.ProposeIncidentResponse(inc, newID)
		},
		WebhookSecret: os.Getenv("TSENGINE_WEBHOOK_SECRET"), PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"),
		// continuous-monitoring: open/resolve incidents from change between passes,
		// alerting a human the moment a new at/above-threshold issue appears.
		Detector: &detect.Detector{Store: st, Recorder: rec, Alerter: incidentAlerter, NewID: newID,
			// Maintenance-window suppression: during an active change-freeze, open no incidents and
			// page no one (resolves still flow). Reads the tenant's windows at evaluation time.
			Suppressed: func(ctx context.Context, tenantID string, now time.Time) bool {
				t, err := st.GetTenant(ctx, tenantID)
				if err != nil {
					return false
				}
				_, active := t.InMaintenance(now)
				return active
			},
		},
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

	// Scans run off the request path on a bounded worker pool, so "Scan now" / webhook
	// re-scans never block the API (a scan can take minutes). Single-box; swap for a
	// durable queue to scale out.
	scanJobs := jobs.NewPool(scanWorkers(), 256, 2000, scanJobTimeout(), newID)
	obsv.RegisterScanJobsInflight(func() float64 { return float64(scanJobs.Inflight()) })
	// Live active-exploitation is opt-in at the operator level (belt-and-suspenders on
	// top of per-engagement explicit consent): only wire a live Prober when
	// TSENGINE_ACTIVE_EXPLOIT=1. Absent → active engagements run the passive driver.
	var prober pentest.Prober
	if os.Getenv("TSENGINE_ACTIVE_EXPLOIT") == "1" {
		prober = pentest.NewHTTPProber()
		log.Print("[platform] live active-exploitation ENABLED (TSENGINE_ACTIVE_EXPLOIT=1) — consent-gated per engagement")
	}
	// OAST collaborator for blind-class proof in deep (autonomous) mode (ADR-0008 D2). Absent
	// (TSENGINE_OAST_POLL_URL unset) → blind classes stay unproven leads, never false positives.
	interactor := pentest.NewInteractorFromEnv()
	if interactor != nil {
		log.Print("[platform] OAST collaborator wired (TSENGINE_OAST_POLL_URL) — blind-class proof enabled for deep pentests")
	}
	// Headless-browser channel for DOM-XSS / client-side proof in deep mode (ADR-0008 D3).
	// Nil (the chromedp impl is sandbox-gated) → those classes stay leads.
	browser := pentest.NewBrowserFromEnv()
	api := platformapi.NewHandler(platformapi.Deps{
		Store: st, Connectors: reg, Runner: svc, Desk: desk, GRC: g, Vault: vault, Jobs: scanJobs,
		Recorder: rec, // sign HITL acts (risk/policy/audit/pentest) into the ledger — §18.2 inv. 4
		Token:    token, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"),
		SlackSigningSecret: os.Getenv("TSENGINE_SLACK_SIGNING_SECRET"),
		WebhookSecret:      os.Getenv("TSENGINE_WEBHOOK_SECRET"), NewID: newID, Prober: prober, Interactor: interactor, Browser: browser,
	})
	// The human-facing dashboard (HTML) shares the same bearer token as the API (via a
	// browser session cookie) and drives the SAME gated desk for approvals. It falls
	// through to the API for every non-/ui path.
	ui := console.Handler(console.Deps{Store: st, Token: token, Desk: desk, Report: g,
		Connectors: reg, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"), Rescan: svc})
	mux := http.NewServeMux()
	mux.Handle("/metrics", obsv.MetricsHandler()) // Prometheus scrape target (network-restrict in prod)
	mux.Handle("/ui", ui)
	mux.Handle("/ui/", ui)
	mux.Handle("/", api)
	// obsv.Middleware is the outermost wrapper: per-request metrics + a structured access log.
	srv := &http.Server{Addr: addr, Handler: obsv.Middleware(mux), ReadHeaderTimeout: 10 * time.Second}

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
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)      // stop accepting requests
	_ = scanJobs.Shutdown(sctx) // let in-flight scans finish (or the deadline cut them off)
}

// scanWorkers is how many tenant re-scans run concurrently off the request path.
func scanWorkers() int {
	if v := os.Getenv("TSENGINE_SCAN_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 2
}

// scanJobTimeout bounds a single tenant re-scan job. Default 30m.
func scanJobTimeout() time.Duration {
	if v := os.Getenv("TSENGINE_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Minute
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

// fileSecretKeys are the sensitive env vars that may be supplied as a mounted file via the
// Docker-secret "<KEY>_FILE" convention instead of an inline env value.
var fileSecretKeys = []string{
	"TSENGINE_SECRET_KEY", "TSENGINE_PLATFORM_TOKEN", "TSENGINE_WEBHOOK_SECRET",
	"GITHUB_CLIENT_SECRET", "GITLAB_CLIENT_SECRET", "OKTA_CLIENT_SECRET",
	"GWORKSPACE_CLIENT_SECRET", "M365_CLIENT_SECRET",
}

// hydrateFileSecrets implements the Docker-secret "*_FILE" convention: for each sensitive
// key, if KEY is unset but KEY_FILE points at a readable file, load the file's trimmed
// contents into KEY. This keeps secrets (the AES sealing key, the platform token) out of
// inline compose env — they ride as mounted files / Docker secrets instead. An already-set
// KEY always wins; an unreadable KEY_FILE is warned and skipped (never fatal here — the
// downstream required-secret checks still apply).
func hydrateFileSecrets() {
	for _, key := range fileSecretKeys {
		if os.Getenv(key) != "" {
			continue // an explicit inline value wins
		}
		path := os.Getenv(key + "_FILE")
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[platform] WARNING: %s_FILE=%q unreadable: %v", key, path, err)
			continue
		}
		_ = os.Setenv(key, strings.TrimSpace(string(b)))
	}
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

// openStore returns the durable store for TSENGINE_PLATFORM_DB (a *.db/*.sqlite path →
// SQLite, the production single-box backend; a *.json path → the whole-snapshot file
// store), else an in-memory store. Routing lives in store.Open; this wraps it with
// startup logging + fatal-on-error.
func openStore() store.Store {
	path := os.Getenv("TSENGINE_PLATFORM_DB")
	s, err := store.Open(path)
	if err != nil {
		log.Fatalf("[platform] open store %s: %v", path, err)
	}
	switch {
	case path == "":
		log.Print("[platform] in-memory store (set TSENGINE_PLATFORM_DB=/data/platform.db to persist)")
	case strings.HasSuffix(strings.ToLower(path), ".json"):
		log.Printf("[platform] file store at %s", path)
	default:
		log.Printf("[platform] sqlite store at %s", path)
	}
	return s
}
