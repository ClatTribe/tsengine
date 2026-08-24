// Command platform is the multi-tenant server for the autonomous security team
// (docs/autonomous-team.md). It wires the store + connectors + the engine
// (EngineRunner over a per-asset sandbox) + the HITL desk + remediation + GRC behind
// the platformapi HTTP surface AND the human-facing console (/ui), running the full
// loop: onboard → connect → scan → propose → gate → record compliance, every decision
// signed into the ledger. The console makes that loop clickable end to end: sign in →
// connect a system (OAuth) → posture dashboard → approve/reject fixes → compliance
// report.
//
// Durability: the store is chosen by TSENGINE_PLATFORM_DB (see openStore) — a durable local
// SQLite file by default, a postgres:// DSN to deploy on managed Postgres. AES-256-GCM token
// sealing is TSENGINE_SECRET_KEY. A cloud-KMS vault is the scale-out successor behind the same
// interface. Set TSENGINE_PLATFORM_NO_ENGINE=1 to boot without the sandbox engine (connect /
// list / webhook-accept / operate-workspace only).
//
// Env:
//
//	TSENGINE_PLATFORM_TOKEN     static platform bearer token (required)
//	TSENGINE_PLATFORM_DB        store selector: unset → SQLite file "platform.db"; a postgres:// DSN
//	                            → Postgres; a *.db/*.sqlite path → SQLite; *.json → file; "memory" → in-memory
//	TSENGINE_PLATFORM_ADDR      listen address (default :8090)
//	TSENGINE_PLATFORM_PUBLIC    public base URL for OAuth redirect_uri
//	TSENGINE_SANDBOX_IMAGE      scan sandbox image ref (default tsengine/sandbox:latest)
//	TSENGINE_PENTEST_SANDBOX_IMAGE  pentest (exploitation) sandbox image; unset → falls back to the scan image
//	TSENGINE_PLATFORM_NO_ENGINE 1 → boot without the sandbox engine
//	TSENGINE_MONITOR_INTERVAL  continuous re-scan cadence (e.g. 6h; default 12h; 0 disables)
//	TSENGINE_SKILLS_DIR         Detection Skills library dir (ADR 0017); unset → ./skills if present,
//	                           else triage annotation is off. A misconfigured path disables it rather
//	                           than falling back to a library the operator did not choose.
//	TSENGINE_THREAT_INTEL_CORPUS  path to the GLOBAL KEV/EPSS corpus file (else embedded snapshot)
//	TSENGINE_CORPUS_REFRESH_INTERVAL  global threat-intel refresh cadence (default 24h; 0 disables)
//	TSENGINE_EXPLOIT_INTEL     1 → also build the offensive-face exploit-intel sidecar (ADR 0019)
//	                           from the nuclei-templates archive on each corpus refresh (opt-in; the
//	                           L2 pentester's bounded exploitation-checker reads it). Off by default.
//	TSENGINE_EXPLOIT_INTEL_URL pin a tag/commit nuclei-templates tarball for the sidecar (reproducible)
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	repoasset "github.com/ClatTribe/tsengine/internal/asset/repository"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/apiauthz"
	"github.com/ClatTribe/tsengine/internal/assetregistry"
	"github.com/ClatTribe/tsengine/internal/attest"
	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudhistory"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/connector/awsfetch"
	"github.com/ClatTribe/tsengine/internal/connector/awsremediate"
	"github.com/ClatTribe/tsengine/internal/connector/azremediate"
	"github.com/ClatTribe/tsengine/internal/connector/cloudprobe"
	"github.com/ClatTribe/tsengine/internal/connector/gcpremediate"
	"github.com/ClatTribe/tsengine/internal/console"
	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/detectionskill"
	"github.com/ClatTribe/tsengine/internal/email"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/jobs"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/notify"
	"github.com/ClatTribe/tsengine/internal/obsv"
	"github.com/ClatTribe/tsengine/internal/operate"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/platformapi"
	"github.com/ClatTribe/tsengine/internal/ratelimit"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/scheduler"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	_ "github.com/ClatTribe/tsengine/internal/toolsbundle" // register OSS tools so host-side PlanAnchors resolves anchors (else 0 findings)
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
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
	// Listen address: an explicit TSENGINE_PLATFORM_ADDR wins; else honor the PaaS-injected $PORT
	// (Render / Railway / Fly / Heroku set it and require the app to bind it); else :8090.
	addr := os.Getenv("TSENGINE_PLATFORM_ADDR")
	if addr == "" {
		if p := os.Getenv("PORT"); p != "" {
			addr = ":" + p
		} else {
			addr = ":8090"
		}
	}
	image := envOr("TSENGINE_SANDBOX_IMAGE", "tsengine/sandbox:latest")
	// Two-image split (docs/product-restructure.md P4): the SCAN dispatcher uses the detection image; the
	// leaner PENTEST image (docker/pentest-sandbox/Dockerfile) carries the exploitation toolset. Pentest
	// falls back to the scan image when TSENGINE_PENTEST_SANDBOX_IMAGE is unset, so single-image deploys
	// are unchanged.
	sandboxImages := sandbox.ResolveImages(image, os.Getenv("TSENGINE_PENTEST_SANDBOX_IMAGE"))
	log.Printf("[platform] sandbox images — scan=%s pentest=%s (set TSENGINE_PENTEST_SANDBOX_IMAGE to split the exploitation toolset into a leaner image; unset → both use the scan image)",
		sandboxImages.Scan, sandboxImages.Pentest)

	// PER-ASSET SCAN IMAGES. TSENGINE_SANDBOX_IMAGE_TEMPLATE (containing "{toolset}") opts the whole
	// deployment into the slim per-asset images CI publishes, so a box that only scans repositories
	// stops pulling codeql, prowler and scoutsuite. Unset → every asset uses the full image,
	// which is exactly today's behaviour.
	scanImages := sandbox.ScanImages{
		Full:     sandboxImages.Scan,
		Template: os.Getenv("TSENGINE_SANDBOX_IMAGE_TEMPLATE"),
	}
	// Log the RESOLVED image per asset, not the template. An operator who mistypes the placeholder
	// gets the full image everywhere and no error — the fallback is deliberate (§10: never guess an
	// image name), which means the only way to see it took effect is to print what it resolved to.
	for _, at := range types.AllAssetTypes() {
		if img, slim := scanImages.For(at); slim {
			log.Printf("[platform] scan image for %-18s %s (slim)", at, img)
		} else {
			log.Printf("[platform] scan image for %-18s %s (full)", at, img)
		}
	}

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
	} else if err := requireSealedSecrets(os.Getenv("TSENGINE_ALLOW_UNSEALED_SECRETS")); err != nil {
		// FAIL CLOSED: without a sealing key, OAuth tokens / customer credentials would be written to
		// the store in PLAINTEXT. For a security product that is never an acceptable silent default, so
		// the platform refuses to start unless a dev has explicitly opted into plaintext.
		log.Fatalf("[platform] %v", err)
	} else {
		log.Print("[platform] WARNING: tokens stored UNSEALED (TSENGINE_ALLOW_UNSEALED_SECRETS=1, dev only) — set TSENGINE_SECRET_KEY (base64 32 bytes) in production")
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
	g := &grc.GRC{Store: st, ControlUniverse: hooks.NewCompliance().ControlsFor}

	// The continuous-monitoring detector — shared by the runner (full open/resolve each pass) AND the
	// API's event-driven ingest paths (identity / SaaS), which call detector.OpenFor to open incidents
	// for a freshly-ingested high threat WITHOUT the resolve sweep.
	detector := &detect.Detector{Store: st, Recorder: rec, Alerter: incidentAlerter, NewID: newID,
		// Bound per-pass paging so a bulk event (e.g. a whole org's MFA export) doesn't storm the
		// on-call. Every incident still opens + shows in the UI; under-attack incidents always page.
		AlertCap: 25,
		// Maintenance-window suppression: during an active change-freeze, open no incidents and page
		// no one (resolves still flow). Reads the tenant's windows at evaluation time.
		Suppressed: func(ctx context.Context, tenantID string, now time.Time) bool {
			t, err := st.GetTenant(ctx, tenantID)
			if err != nil {
				return false
			}
			_, active := t.InMaintenance(now)
			return active
		},
	}

	// ctFetcher is the bounded HTTP fetcher the continuous-OSINT sync uses for crt.sh (fixed public
	// host, domain is a query param → no SSRF surface; keyless, no sandbox).
	ctFetcher := func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "tsengine-osint")
		resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}

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
		Detector: detector,
		// continuous external-exposure: each pass runs the keyless crt.sh CT collector over the
		// tenant's domains so a newly-exposed host becomes an incident (the crt.sh host is fixed —
		// the domain is a query param — so a bounded client is safe; no key, no sandbox).
		OSINTFetcher: ctFetcher,
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
		engine := &runner.EngineRunner{
			Resolve:       assetregistry.HandlerFor,
			NewDispatcher: sandboxDispatcher(scanImages, st, vault),
			// The workspace-aware factory + the code surface's validation rung (ADR 0029 D2a). Wired
			// HERE rather than left as a seam, because a capability reachable only from a test is the
			// defect this ADR exists to stop repeating.
			NewDispatcherWithWorkspace: sandboxDispatcherWS(scanImages, st, vault),
			Reachability:               runner.TriageReachability,
		}
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
	var authzProber apiauthz.Prober
	if os.Getenv("TSENGINE_ACTIVE_EXPLOIT") == "1" {
		prober = pentest.NewHTTPProber()
		authzProber = apiauthz.LiveProber() // enables POST /v1/assets/{id}/authz-test/run (BOLA/BFLA), consent-gated per request
		log.Print("[platform] live active-exploitation ENABLED (TSENGINE_ACTIVE_EXPLOIT=1) — consent-gated per engagement")
	}
	// OAST collaborator for blind-class proof in deep (autonomous) mode (ADR-0008 D2). Absent
	// (TSENGINE_OAST_POLL_URL unset) → blind classes stay unproven leads, never false positives.
	interactor := pentest.NewInteractorFromEnv()
	if interactor != nil {
		log.Print("[platform] OAST collaborator wired (TSENGINE_OAST_POLL_URL) — blind-class proof enabled for deep pentests")
	}
	// Headless-browser channel for DOM-XSS / client-side proof in deep mode (ADR-0008 D3).
	// Host-side chromedp (§12.6 — no sandbox rebuild), gated by TSENGINE_HEADLESS_BROWSER and
	// a Chrome binary on the host. Nil when unconfigured → those classes stay unproven leads,
	// never false positives.
	browser := pentest.NewBrowserFromEnv()
	if browser != nil {
		log.Print("[platform] headless-browser channel wired (TSENGINE_HEADLESS_BROWSER) — DOM-XSS / client-side execution proof enabled for deep pentests")
	}
	// ModeDeep D-agent: the LLM spec generator. cloudengine.LLMFromEnv resolves a cloud key OR a local
	// Ollama (LLM_BASE_URL); nil when neither is configured → the deterministic HeuristicSpecGen.
	var agentLLM pentest.SpecLLM
	if llm, ok := cloudengine.LLMFromEnv(); ok {
		agentLLM = llm
		log.Print("[platform] ModeDeep D-agent wired (LLM spec generator) — open-ended exploitation proposals, deterministically validated")

		// Detection Skills (ADR 0017): load the library and attach it to the detector so an opening
		// incident carries the detection engineer's reasoning instead of only a severity.
		// NewTriager returns nil for an empty library, so this is safe to assign unconditionally — a
		// deploy with no skills keeps exactly today's behaviour.
		//
		// A skill is UNTRUSTED input: one that claims capability, or fails to parse, is refused at
		// load and logged HERE rather than silently dropped. A hostile skill sitting in the directory
		// should be visible in the boot log, not swallowed.
		if dir := skillsDir(); dir != "" {
			lib, skillErrs := detectionskill.LoadDir(dir)
			for _, e := range skillErrs {
				log.Printf("[platform] WARNING: skill refused: %v", e)
			}
			if tri := detectionskill.NewTriager(lib, llm); tri != nil {
				detector.Triager = tri
				log.Printf("[platform] Detection Skills wired (%d from %s): %v",
					len(lib), dir, detectionskill.Library(lib).Names())
			}
		}
	}
	// The L2 Lead/translator's tool-calling client (POST /v1/l2/translate). Anthropic, OpenAI, or a
	// local Ollama via l2.ClientFromEnv; nil → the translator endpoint is gated.
	leadClient := l2.ClientFromEnv()
	if leadClient != nil {
		log.Printf("[platform] L2 translator wired (model=%s) — developer-facing consultant deliverable", leadClient.Model())
	}
	// Cloud-snapshot store: persists each tenant's last cloud inventory so the AI cloud engineer can
	// reason over STORED cloud state (the prerequisite for L2→cloudagent delegation). File-backed when
	// TSENGINE_CLOUDSNAP_DIR is set (durable on a single box), else in-process.
	var cloudSnaps cloudsnap.Store = cloudsnap.NewMemStore()
	if dir := os.Getenv("TSENGINE_CLOUDSNAP_DIR"); dir != "" {
		if fs, ferr := cloudsnap.NewFileStore(dir); ferr != nil {
			log.Printf("[platform] cloudsnap file store (%s): %v — using in-process", dir, ferr)
		} else {
			cloudSnaps = fs
		}
	}
	// The estate TIMELINE — the other half of the snapshot store. cloudsnap is latest-wins (what the
	// agent reasons over now); this is append-only with change detection, so "when did this bucket become
	// public?" is answerable. Shares TSENGINE_CLOUDSNAP_DIR: both are cloud-state at rest, and a deployment
	// that wants one durable wants the other, so a second env var would only be a way to get it half-on.
	var cloudHist cloudhistory.Store = cloudhistory.NewMemStore()
	if dir := os.Getenv("TSENGINE_CLOUDSNAP_DIR"); dir != "" {
		if fs, ferr := cloudhistory.NewFileStore(dir); ferr != nil {
			log.Printf("[platform] cloud history file store (%s): %v — using in-process", dir, ferr)
		} else {
			cloudHist = fs
		}
	}
	apiDeps := platformapi.Deps{
		Store: st, Connectors: reg, Runner: svc, Desk: desk, Submitter: desk, GRC: g, Vault: vault, Jobs: scanJobs,
		// SIGNED compliance evidence pack (ADR 0031 D2b): the auditor-facing artifact is ed25519-
		// attested with the platform's key. Nil-safe downstream — without a key the endpoint
		// returns 501 rather than serving an unsigned artifact from a signed route.
		EvidenceSigner: func() (ed25519.PrivateKey, string, error) { return attest.LoadOrCreate(attest.DefaultKeyPath()) },
		// The DETECTION corpus's identity, so the VAPT report can say what was capable of finding
		// things — not only how old the threat intel was. A mutable tag here makes the report say it
		// cannot identify the build, which is the honest answer and the one that prompts a rebuild.
		ScanImage: sandboxImages.Scan,
		// Per-tenant fair-use rate limiting on the authenticated API (plan.APIRatePerMin):
		// one tenant's runaway automation can't degrade the shared platform, and paid
		// tiers get more headroom. Fail-open (generous defaults; Enterprise unmetered).
		RateLimiter: ratelimit.New(),
		// Ingested findings reach the approval desk with the SAME proposer the runner uses.
		ProposeFix: func(f types.Finding, a platform.Asset) (platform.Action, bool) { return remediate.Propose(f, a, newID) },
		// LIVE cloud read: assume the customer's read-only role recorded at connect time. The role ARN
		// IS the credential (connector.AWS.Exchange), and the tenant id is the external-id guard issued
		// on the connect link (confused-deputy protection).
		AWSFetcher: func(c platform.Connection) awsfetch.Fetcher {
			return awsfetch.Fetcher{
				AccountID:  c.Account,
				Buckets:    awsfetch.NewS3Lister(os.Getenv("AWS_REGION"), c.SecretRef, c.TenantID),
				Principals: awsfetch.NewIAMLister(os.Getenv("AWS_REGION"), c.SecretRef, c.TenantID),
				Compute:    awsfetch.NewEC2Lister(os.Getenv("AWS_REGION"), c.SecretRef, c.TenantID),
			}
		},
		// LIVE provider dry-run (ADR 0024 P1a's remaining half): ask AWS's own policy simulator whether
		// a move is authorized, through the SAME scoped read-only role recorded at connect time.
		// iam:SimulatePrincipalPolicy is a READ, so this needs no new credential and no new consent —
		// the role ARN is c.SecretRef and the tenant id is the external-id guard, exactly as AWSFetcher
		// above. Nil connection → proberOrNil returns nil → check_reachable says the provider was not
		// asked, rather than reporting a path proven or unproven.
		CloudProber: func(c platform.Connection) cloudagent.ExploitProber {
			return &cloudprobe.Prober{
				Sim: cloudprobe.NewAWSSimulator(os.Getenv("AWS_REGION"), c.SecretRef, c.TenantID),
				// The stamp layout is load-bearing: ADR 0024 P1c parses it to age a proof, and a
				// differently-formatted one would make every proof unreadable and so StandingUnknown.
				Now: platformapi.ProbeStamp,
			}
		},
		CloudSnapshots: cloudSnaps,
		CloudHistory:   cloudHist,
		Recorder:       rec,      // sign HITL acts (risk/policy/audit/pentest) into the ledger — §18.2 inv. 4
		IncidentOpener: detector, // open incidents for event-driven ingest (identity/SaaS) — OpenFor, no resolve sweep
		Detector:       detector, // reconcile a pentest run's findings into incidents immediately (detect-&-respond)
		Token:          token, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"),
		// AppURL lands the user back in the app after OAuth (else they'd see a raw JSON blob).
		// Defaults to the public base (same-origin behind the TLS edge), override with TSENGINE_APP_URL.
		AppURL:             envOr("TSENGINE_APP_URL", os.Getenv("TSENGINE_PLATFORM_PUBLIC")),
		SlackSigningSecret: os.Getenv("TSENGINE_SLACK_SIGNING_SECRET"),
		WebhookSecret:      os.Getenv("TSENGINE_WEBHOOK_SECRET"), NewID: newID, Prober: prober, AuthzProber: authzProber, Interactor: interactor, Browser: browser, AgentLLM: agentLLM, LeadClient: leadClient,
		Mailer: email.FromEnv(), // transactional email (password reset/invite); no-op until SMTP_* is set
	}
	// Auto-review (framework: auto-invoke the AI Security Engineer after a scan): when a monitoring pass
	// surfaces something NEW, the engineer reviews the estate automatically instead of waiting for a
	// human to click /v1/l2/translate. The hook self-gates (AIEnabled + an available LLM), so it's a
	// no-op when AI isn't entitled/configured — a Free tenant never auto-spends the operator's budget.
	// Fill a missing CWE on a scanner finding before the L1.5 chain runs, so compliance.map can map
	// it to controls (§8). No tenant model → a no-op, which is also how the Free plan's AI gate
	// reaches it.
	svc.AttributeCWEs = apiDeps.CWEAttributor()
	svc.AfterScan = apiDeps.AutoReviewAfterScan
	// Close the find → fix → prove-it-is-dead loop: each monitoring pass re-runs the exploit for
	// findings an APPLIED fix claimed to close, so a verification can be upgraded from absence to
	// closure — or downgraded when the exploit still works. Doubly gated inside the adapter: the
	// operator must have enabled live probing (TSENGINE_ACTIVE_EXPLOIT), and the tenant must have
	// proven ownership of the target. Both fail closed and report "unverified" rather than "clean".
	svc.Reattacker = apiDeps.ReattackVerdicts
	// Make the connected cloud account continuously monitored, like SaaS posture and OSINT already
	// are. Each pass re-reads the account through its read-only role and diffs it against the previous
	// snapshot, so a bucket that turned public or a principal that gained admin opens an incident on
	// its own. Everything below this line already existed — the fetcher, the drift diff, the incident
	// opener — but only a human pressing Sync ever ran it, which made cloud the one connected surface
	// whose change detection was manual. Self-gating: a tenant with no AWS connection, or a deployment
	// with no fetcher wired, reports "unavailable" and the pass carries on.
	svc.CloudSyncer = func(ctx context.Context, tenantID string) ([]types.Finding, error) {
		drift, _, err := apiDeps.SyncCloudInventory(ctx, tenantID)
		return drift, err
	}

	// The RESPOND half for EVENT-DRIVEN incidents: when an ingest path (identity/cloud-drift/OSINT/…)
	// opens a new incident via detector.OpenFor, put the AI engineer on it immediately instead of
	// waiting for the next scan. Same gating as AfterScan (own key any plan; operator LLM AI-entitled
	// only), detached so it never blocks the ingest request. Set after apiDeps is built (the detector
	// holds a back-reference to the Deps that drive the review) — the same wiring shape as AfterScan.
	detector.Responder = apiDeps
	// Continuous pentesting: each monitoring pass runs any engagement whose recurring schedule is due
	// (a safe PASSIVE re-verify — never auto active exploitation). Self-gating (no-op when nothing is due).
	svc.AfterPass = func(ctx context.Context, tenantID string) {
		apiDeps.RunDuePentests(ctx, tenantID)
		// Doubt→prove: record which unproven findings are worth an exploit attempt. Proposes only —
		// active exploitation stays consent-gated, so this never launches an engagement by itself.
		apiDeps.RecordProofQueue(ctx, tenantID)
		// Cross-surface detection, every pass. It belongs HERE rather than at each ingest handler
		// because a cross-surface fact needs two surfaces, and the second one can arrive through any
		// of a dozen doors — or through a scan, which is not a door at all. Two ingests trigger it
		// directly for immediate feedback; this is what guarantees the join is eventually found no
		// matter how its halves arrived. Deterministic and LLM-free, so unlike the auto-review it
		// needs no change-gate to be affordable, and its findings carry content-derived ids so
		// re-running over an unchanged estate updates rather than duplicates.
		apiDeps.DetectEstateEachPass(ctx, tenantID)
	}
	api := platformapi.NewHandler(apiDeps)
	// The human-facing dashboard (HTML) shares the same bearer token as the API (via a
	// browser session cookie) and drives the SAME gated desk for approvals. It falls
	// through to the API for every non-/ui path.
	ui := console.Handler(console.Deps{Store: st, Token: token, Desk: desk, Report: g,
		Connectors: reg, PublicURL: os.Getenv("TSENGINE_PLATFORM_PUBLIC"), Rescan: svc,
		// Mint the SAME signed OAuth state the /v1 callback verifies (keyed by the platform token), so
		// console onboarding stays on the one signed-state contract instead of a (rejected) raw tenant id.
		StateSigner: func(tenantID string) string { return platformapi.SignOAuthState(token, tenantID) }})
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

	// GLOBAL threat-intel auto-refresh: keep the shared KEV/EPSS corpus current on its own (slower)
	// clock, so "continuously updating" intel doesn't depend on an external ops cron. Disabled unless
	// TSENGINE_THREAT_INTEL_CORPUS points at a corpus file (else the engine uses its embedded snapshot).
	corpusRefresher := &scheduler.CorpusRefresher{
		DataPath:        os.Getenv("TSENGINE_THREAT_INTEL_CORPUS"),
		Interval:        corpusRefreshInterval(),
		ExploitIntelURL: exploitIntelURL(), // ADR 0019: opt-in offensive-face sidecar for the L2 pentester
		VulnrichmentURL: vulnrichmentURL(),
		NVDURL:          strings.TrimSpace(os.Getenv("TSENGINE_NVD_URL")), // opt-in 7th feed: CISA's SSVC decision points
	}
	go func() { _ = corpusRefresher.Run(monitorCtx) }()

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

func repoScratchDir() string {
	d := strings.TrimSpace(os.Getenv("TSENGINE_REPO_SCRATCH"))
	if d == "" {
		return ""
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		log.Printf("[platform] WARNING: TSENGINE_REPO_SCRATCH=%q unusable (%v) — falling back to default temp dir", d, err)
		return ""
	}
	return d
}

// sandboxDispatcher returns a factory that spawns a per-asset sandbox and hands back
// the orchestrator Dispatcher + a teardown. Mirrors cmd/tsengine's scan path.
//
// It is the workspace-unaware adapter over sandboxDispatcherWS, kept because EngineRunner.ReplayTool
// takes this shape and a replay has no use for the source tree.
func sandboxDispatcher(images sandbox.ScanImages, st store.Store, vault secret.Vault) func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, func(), error) {
	ws := sandboxDispatcherWS(images, st, vault)
	return func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, func(), error) {
		disp, _, cleanup, err := ws(ctx, a)
		return disp, cleanup, err
	}
}

// sandboxDispatcherWS is the real factory. It additionally reports the HOST PATH of the repository
// clone it made for this scan (empty for every other asset type), so the scan can run host-side
// analysis over the tree while it exists — ADR 0029 D2a.
//
// The clone's whole lifetime is this dispatcher's: created here, torn down by the returned cleanup.
// Anything that needs the tree has to run inside that window, which is why the path is returned
// rather than left implicit.
func sandboxDispatcherWS(images sandbox.ScanImages, st store.Store, vault secret.Vault) func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, string, func(), error) {
	return func(ctx context.Context, a platform.Asset) (orchestrator.Dispatcher, string, func(), error) {
		// The per-asset image: slim when a template is configured and this asset has a toolset,
		// else the full image. Resolved per scan rather than once, so the asset decides.
		scanImage, _ := images.For(types.AssetType(a.Type))
		opts := sandbox.SpawnOptions{Image: scanImage}
		var cloneDir string
		switch types.AssetType(a.Type) {
		case types.AssetCloudAccount:
			opts.Env = cloudCredentialEnv()
		case types.AssetRepository:
			dir, err := os.MkdirTemp(repoScratchDir(), "tsengine-repo-*")
			if err != nil {
				return nil, "", nil, fmt.Errorf("sandboxDispatcher: temp dir: %w", err)
			}
			if cerr := os.Chmod(dir, 0o755); cerr != nil {
				_ = os.RemoveAll(dir)
				return nil, "", nil, fmt.Errorf("sandboxDispatcher: chmod temp dir: %w", cerr)
			}
			auth, aerr := repoAuth(ctx, st, vault, a)
			if aerr != nil {
				_ = os.RemoveAll(dir)
				return nil, "", nil, aerr
			}
			if _, cerr := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
				URL: repoCloneURL(a), Auth: auth, Depth: 1, SingleBranch: true,
			}); cerr != nil {
				_ = os.RemoveAll(dir)
				return nil, "", nil, fmt.Errorf("sandboxDispatcher: clone %s: %w", a.Target, cerr)
			}
			cloneDir = dir
			opts.Mounts = append(opts.Mounts, sandbox.Mount{HostPath: dir, ContainerPath: repoasset.WorkspacePath})
		}
		info, err := sandbox.Spawn(ctx, opts)
		if err != nil {
			if cloneDir != "" {
				_ = os.RemoveAll(cloneDir)
			}
			return nil, "", nil, err
		}
		cleanup := func() {
			_ = sandbox.Destroy(context.Background(), info)
			if cloneDir != "" {
				_ = os.RemoveAll(cloneDir)
			}
		}
		return sandbox.NewClient(info), cloneDir, cleanup, nil
	}
}

func repoCloneURL(a platform.Asset) string {
	if a.Target != "" {
		return a.Target
	}
	if full := a.Meta["full_name"]; full != "" {
		return "https://github.com/" + full + ".git"
	}
	return a.Target
}

func repoAuth(ctx context.Context, st store.Store, vault secret.Vault, a platform.Asset) (transport.AuthMethod, error) {
	if a.Meta["private"] != "true" {
		return nil, nil
	}
	conns, err := st.ListConnections(ctx, a.TenantID)
	if err != nil {
		return nil, fmt.Errorf("sandboxDispatcher: list connections: %w", err)
	}
	for _, c := range conns {
		if c.ID != a.ConnectionID {
			continue
		}
		token, oerr := vault.Open(c.SecretRef)
		if oerr != nil {
			return nil, fmt.Errorf("sandboxDispatcher: open token: %w", oerr)
		}
		if token == "" {
			return nil, fmt.Errorf("sandboxDispatcher: empty token %s", c.ID)
		}
		return &githttp.BasicAuth{Username: "x-access-token", Password: token}, nil
	}
	return nil, fmt.Errorf("sandboxDispatcher: connection %s not found", a.ConnectionID)
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
// requireSealedSecrets fails closed when no AES sealing key is configured: without it OAuth tokens and
// customer credentials would be persisted in PLAINTEXT. It returns an error (→ startup fatal) unless a
// dev has explicitly opted into plaintext with TSENGINE_ALLOW_UNSEALED_SECRETS=1.
func requireSealedSecrets(allowUnsealed string) error {
	if allowUnsealed == "1" {
		return nil
	}
	return errors.New("refusing to start without TSENGINE_SECRET_KEY: OAuth tokens/credentials would be stored in PLAINTEXT. " +
		"Set TSENGINE_SECRET_KEY (base64 32 bytes), or set TSENGINE_ALLOW_UNSEALED_SECRETS=1 to allow plaintext in a dev environment")
}

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

// corpusRefreshInterval is the GLOBAL threat-intel refresh cadence (TSENGINE_CORPUS_REFRESH_INTERVAL,
// e.g. "24h"). Default 24h (KEV/EPSS update at most daily); "0" disables the in-process refresher
// (rely on an external `tsengine corpus refresh` cron instead).
// exploitIntelURL returns the nuclei-templates archive URL used to build the OFFENSIVE-face
// exploit-intel sidecar (ADR 0019), or "" to leave it unbuilt (the default — the offensive seam stays
// dormant). Opt IN with TSENGINE_EXPLOIT_INTEL=1 (uses the project's main-branch archive) or pin a
// tag/commit tarball with TSENGINE_EXPLOIT_INTEL_URL for a reproducible evidence pack. Only meaningful
// when TSENGINE_THREAT_INTEL_CORPUS is set (the sidecar is written beside that corpus file).
func exploitIntelURL() string {
	if u := strings.TrimSpace(os.Getenv("TSENGINE_EXPLOIT_INTEL_URL")); u != "" {
		return u
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TSENGINE_EXPLOIT_INTEL"))) {
	case "1", "true", "yes", "on":
		return threatintel.ExploitIntelURL
	}
	return ""
}

// vulnrichmentURL enables the SSVC feed, mirroring exploitIntelURL.
//
// It exists because a feed the running platform cannot switch on is a feed nobody has. The parser,
// the corpus field, the enrichment hook, the digest, the finding page and the probe planner were all
// wired before this was — every one of them reachable only from a test.
func vulnrichmentURL() string {
	if u := strings.TrimSpace(os.Getenv("TSENGINE_SSVC_URL")); u != "" {
		return u
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TSENGINE_SSVC"))) {
	case "1", "true", "yes", "on":
		return threatintel.VulnrichmentURL
	}
	return ""
}

func corpusRefreshInterval() time.Duration {
	v := os.Getenv("TSENGINE_CORPUS_REFRESH_INTERVAL")
	if v == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("[platform] bad TSENGINE_CORPUS_REFRESH_INTERVAL %q, using 24h", v)
		return 24 * time.Hour
	}
	return d
}

// openStore selects the store from TSENGINE_PLATFORM_DB. The default (env unset) is a durable
// local SQLite file, so "use SQLite now, switch to Postgres for deploy" needs only a one-line
// env change: set a postgres:// DSN (Supabase/RDS/Neon) at deploy time. Routing itself lives in
// store.Open; this wraps it with the default, an explicit in-memory opt-out, startup logging
// (never the Postgres DSN — it holds a password), and fatal-on-error.
//
//	(unset)            → SQLite file "platform.db"  (local default; durable across restarts)
//	postgres://… DSN   → Postgres                   (the deploy target)
//	*.db / *.sqlite    → SQLite at that path
//	*.json             → whole-snapshot file store
//	"memory"/":memory:"→ ephemeral in-memory (tests / throwaway runs)
func openStore() store.Store {
	path := os.Getenv("TSENGINE_PLATFORM_DB")
	switch path {
	case "":
		path = "platform.db" // local default: durable SQLite, zero config
	case "memory", ":memory:":
		path = "" // explicit opt-in to the ephemeral in-memory store
	}
	s, err := store.Open(path)
	if err != nil {
		log.Fatalf("[platform] open store: %v", err)
	}
	switch {
	case path == "":
		log.Print("[platform] in-memory store (ephemeral; unset TSENGINE_PLATFORM_DB or set a path to persist)")
	case strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://"):
		log.Print("[platform] postgres store (deploy backend)")
	case strings.HasSuffix(strings.ToLower(path), ".json"):
		log.Printf("[platform] file store at %s", path)
	default:
		log.Printf("[platform] sqlite store at %s", path)
	}
	return s
}

// skillsDir resolves the Detection Skills library directory (ADR 0017).
//
// TSENGINE_SKILLS_DIR wins when set — an operator pointing at a curated library must never be
// silently overridden by a bundled one. Otherwise the repo's own ./skills is used when it exists,
// which is what a source deploy gets. Returns "" when neither is present, so triage stays off
// rather than the platform guessing at a path.
func skillsDir() string {
	if d := strings.TrimSpace(os.Getenv("TSENGINE_SKILLS_DIR")); d != "" {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
		// Configured but unusable is an operator error worth surfacing — not a silent fallback to a
		// different library than the one they asked for.
		log.Printf("[platform] WARNING: TSENGINE_SKILLS_DIR=%q is not a readable directory — Detection Skills disabled", d)
		return ""
	}
	if st, err := os.Stat("skills"); err == nil && st.IsDir() {
		return "skills"
	}
	return ""
}
