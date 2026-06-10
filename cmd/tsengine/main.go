// Command tsengine is the host-side CLI entry point.
//
// Phase 2:
//
//	tsengine scan   --asset <type> --target <url> [--image <ref>] [--out <dir>]
//	tsengine replay --scan-id <id> --tool <name> [--target <url>] [--out <dir>]
//	tsengine version
//
// scan resolves the per-asset Handler, runs the orchestrator's anchor
// prepass against the sandbox, signs the result, and writes
// runs/<scan_id>/vulnerabilities.json. replay extends an existing scan
// by dispatching one tool through the same boundary.
//
// L1.5 hook chain, registry-tier wrappers, and more anchors land in
// later phases.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	apiasset "github.com/ClatTribe/tsengine/internal/asset/api"
	cloudasset "github.com/ClatTribe/tsengine/internal/asset/cloud"
	containerasset "github.com/ClatTribe/tsengine/internal/asset/container"
	domainasset "github.com/ClatTribe/tsengine/internal/asset/domain"
	ipasset "github.com/ClatTribe/tsengine/internal/asset/ip"
	repoasset "github.com/ClatTribe/tsengine/internal/asset/repository"
	webasset "github.com/ClatTribe/tsengine/internal/asset/web"
	"github.com/ClatTribe/tsengine/internal/attest"
	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/internal/dashboard"
	"github.com/ClatTribe/tsengine/internal/exporter"
	"github.com/ClatTribe/tsengine/internal/findingstore"
	"github.com/ClatTribe/tsengine/internal/gate"
	"github.com/ClatTribe/tsengine/internal/importers"
	"github.com/ClatTribe/tsengine/internal/llmredteam"
	"github.com/ClatTribe/tsengine/internal/loadbench"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/report"
	"github.com/ClatTribe/tsengine/internal/sandbox"
	"github.com/ClatTribe/tsengine/internal/server"
	"github.com/ClatTribe/tsengine/internal/tool"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkov"
	_ "github.com/ClatTribe/tsengine/internal/tool/cloudfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/codeql"
	_ "github.com/ClatTribe/tsengine/internal/tool/cosign"
	_ "github.com/ClatTribe/tsengine/internal/tool/dnstwist"
	_ "github.com/ClatTribe/tsengine/internal/tool/dockle"
	_ "github.com/ClatTribe/tsengine/internal/tool/ffuf"
	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/hadolint"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/hydra"
	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/katana"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
	_ "github.com/ClatTribe/tsengine/internal/tool/naabu"
	_ "github.com/ClatTribe/tsengine/internal/tool/openapi"
	_ "github.com/ClatTribe/tsengine/internal/tool/osvscanner"
	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
	_ "github.com/ClatTribe/tsengine/internal/tool/schemathesis"
	_ "github.com/ClatTribe/tsengine/internal/tool/scoutsuite"
	_ "github.com/ClatTribe/tsengine/internal/tool/seedauth"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/sqlmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/syft"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
	"github.com/ClatTribe/tsengine/internal/tracer"
	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"

	// Side-effect imports register tool wrappers in the global registry.
	// Anchor + registry tier per arch.md.
	_ "github.com/ClatTribe/tsengine/internal/tool/amass"
	_ "github.com/ClatTribe/tsengine/internal/tool/checkdmarc"
	_ "github.com/ClatTribe/tsengine/internal/tool/crtsh"
	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
)

// Version is the engine version reported in vulnerabilities.json.engine.version.
var Version = "0.1.0-dev"

// Persistent signing key, loaded once per process (see signingKey()).
var (
	keyOnce   sync.Once
	keyPriv   ed25519.PrivateKey
	keySigner string
	keyPubHex string
)

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "version":
		fmt.Printf("tsengine %s\n", Version)
	case "scan":
		if err := runScan(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine scan: %v\n", err)
			os.Exit(1)
		}
	case "replay":
		if err := runReplay(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine replay: %v\n", err)
			os.Exit(1)
		}
	case "pubkey":
		if err := runPubkey(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine pubkey: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine verify: %v\n", err)
			os.Exit(1)
		}
	case "corpus":
		if err := runCorpus(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine corpus: %v\n", err)
			os.Exit(1)
		}
	case "cloud-assess":
		if err := runCloudAssess(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine cloud-assess: %v\n", err)
			os.Exit(1)
		}
	case "cloud-investigate":
		if err := runCloudInvestigate(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine cloud-investigate: %v\n", err)
			os.Exit(1)
		}
	case "web-investigate":
		if err := runWebInvestigate(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine web-investigate: %v\n", err)
			os.Exit(1)
		}
	case "web-verify":
		if err := runWebVerify(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine web-verify: %v\n", err)
			os.Exit(1)
		}
	case "llm-redteam":
		if err := runLLMRedteam(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine llm-redteam: %v\n", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine report: %v\n", err)
			os.Exit(1)
		}
	case "findings":
		if err := runFindings(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine findings: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine serve: %v\n", err)
			os.Exit(1)
		}
	case "serve-bench":
		if err := runServeBench(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine serve-bench: %v\n", err)
			os.Exit(1)
		}
	case "reachability":
		if err := runReachability(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine reachability: %v\n", err)
			os.Exit(1)
		}
	case "gate":
		if err := runGate(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine gate: %v\n", err)
			os.Exit(1)
		}
	case "import":
		if err := runImport(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine import: %v\n", err)
			os.Exit(1)
		}
	case "correlate":
		if err := runCorrelate(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine correlate: %v\n", err)
			os.Exit(1)
		}
	case "export":
		if err := runExport(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine export: %v\n", err)
			os.Exit(1)
		}
	case "ledger":
		if err := runLedger(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsengine ledger: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "tsengine: unknown subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `tsengine — Go-native security + compliance engine

Usage:
  tsengine version
  tsengine scan   --asset <type> --target <url> [--image <ref>] [--out <dir>]
                  [--auth-cookie <c> | --auth-login-url <url> --auth-username <u> --auth-password <p>]
                  [--snapshot <inventory.json>]   # cloud_account: emit the AI-engineer dual-view
  tsengine replay --scan-id <id> --tool <name> [--target <url>]
  tsengine cloud-assess --snapshot <inventory.json> [--prowler <findings.json>] [--out <assessment.json>]
  tsengine web-investigate --target <url> [--seed <url>,...] [--max-requests N] [--min-interval <dur>] [--max-iters N]
                  [--export-evidence <file.json>] [--ledger <file.json>] [--sign-key <path>] [--signer <id>]
  tsengine web-verify [--pubkey <hex>] <evidence.json>
  tsengine llm-redteam --bench [--seed N] [--n N] [--hardened-frac F] [--ledger <file.json>]   # emulated LLM red-team population
  tsengine report --in <vulnerabilities.json|evidence.json> [--format md|html] [--out <file>] [--org <name>]
  tsengine findings ingest --db <file> --in <vulnerabilities.json|evidence.json>
  tsengine findings list   --db <file> [--status <s>] [--severity <s>] [--open] [--overdue]
  tsengine findings set    --db <file> --id <F-...> [--status <s>] [--owner <who>] [--note <text>]
  tsengine serve  [--addr :8080] [--runs <dir>] [--image <ref>]   # long-running service (tool-replay API + health)
                  # auth token from --token or TSENGINE_API_TOKEN (required)
  tsengine serve-bench --target <url> --token <t> [--requests N] [--concurrency C] [--duration D]
                  # load + auth-correctness benchmark against a running service
  tsengine reachability --repo <dir> (--package <import/path> [--symbol <Name>...] | --sca <findings.json>)
                  # does this codebase actually CALL the vulnerable dependency function? (Go-first)
  tsengine gate   [--in <scan|evidence.json>] [--sca <findings.json> --repo <dir>] [--fail-on <sev>]
                  [--new-only --baseline <fps.json>] [--format text|json|github]   # CI/CD pass/fail gate
  tsengine import --in <file> [--format auto|sarif|snyk|dependabot] [--as scan|sca] [--out <file>]
                  # normalize SARIF / Snyk / GHAS-Dependabot into the engine (then report/findings/gate/reachability)
  tsengine correlate --in <scan1.json> --in <scan2.json> ...
                  # cross-asset attack chains: a finding HERE → a crown jewel THERE (e.g. web leak → cloud admin)
  tsengine export --in <scan|evidence.json> [--format sarif|json] [--out <file>]
                  [--webhook <url> --webhook-token <t> --hmac-secret <s>]   # emit findings OUT (code-scanning / SIEM / SOC)
  tsengine ledger verify [--pubkey <hex>] <ledger.json>          # check the signed agent decision ledger is intact
  tsengine ledger replay <ledger.json>                          # reconstruct the agent's thought→tool→observation trail
  tsengine ledger show   <ledger.json>                          # one-line summary (steps, decisions, signer)
  tsengine pubkey [--key <path>]
  tsengine verify [--pubkey <hex>] <vulnerabilities.json>
  tsengine corpus refresh [--out <dir>] [--timeout <dur>]

Authenticated web scans (web_application): supply a ready session via
--auth-cookie, or form-login credentials via --auth-login-url plus
--auth-username/--auth-password. seed_auth captures the session and the
wave classifier threads it into the detectors.

Asset types: web_application, api, repository, container_image,
             ip_address, domain, cloud_account
See CLAUDE.md and arch.md for the layered architecture.
`)
}

// --- corpus ------------------------------------------------------

// runCorpus handles `tsengine corpus <subcommand>`. Today: `refresh` — the
// out-of-band OSINT ingest (CISA KEV + FIRST.org EPSS) into the pinned,
// per-scan threat-intel corpus the L1.5 hook + L2 query_threat_intel read.
func runCorpus(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("usage: tsengine corpus refresh [--out <dir>] [--timeout <dur>]")
	}
	switch argv[0] {
	case "refresh":
		return runCorpusRefresh(argv[1:])
	default:
		return fmt.Errorf("unknown corpus subcommand %q (want: refresh)", argv[0])
	}
}

func runCorpusRefresh(argv []string) error {
	fs := flag.NewFlagSet("corpus refresh", flag.ContinueOnError)
	out := fs.String("out", "./corpus", "output dir for threat_intel.json + manifest")
	timeout := fs.Duration("timeout", 5*time.Minute, "fetch timeout")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[corpus] refreshing threat-intel from CISA KEV + FIRST.org EPSS …\n")
	m, path, err := threatintel.Refresh(ctx, threatintel.RefreshOptions{OutDir: *out})
	if err != nil {
		return err
	}
	fmt.Printf("threat-intel corpus written: %s\n", path)
	fmt.Printf("  version:    %s\n", m.Version)
	fmt.Printf("  entries:    %d  (KEV %d, EPSS %d)\n", m.EntryCount, m.KEVCount, m.EPSSCount)
	fmt.Printf("  KEV as-of:  %s\n", m.KEVAsOf.Format(time.RFC3339))
	fmt.Printf("  EPSS as-of: %s\n", m.EPSSAsOf.Format(time.RFC3339))
	fmt.Printf("\nUse it in scans:\n  export %s=%s\n", hooks.ThreatIntelCorpusEnv, path)
	return nil
}

// --- scan --------------------------------------------------------

func runScan(argv []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	assetFlag := fs.String("asset", "", "asset type")
	target := fs.String("target", "", "scan target URL/host")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox docker image")
	outDir := fs.String("out", "runs", "output directory (one subdir per scan)")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall scan timeout")
	// Authenticated-scan flags (web_application). Supply EITHER a ready
	// session cookie (--auth-cookie) OR form-login credentials
	// (--auth-login-url + --auth-username + --auth-password). When set,
	// the web Handler prepends a seed_auth dispatch and the wave classifier
	// threads the captured session into the detectors. See arch.md
	// "web_application" auth flow.
	authCookie := fs.String("auth-cookie", "", "session cookie for authenticated scan (web_application)")
	authLoginURL := fs.String("auth-login-url", "", "form login URL for authenticated scan (web_application)")
	authUsername := fs.String("auth-username", "", "login username (with --auth-login-url)")
	authPassword := fs.String("auth-password", "", "login password (with --auth-login-url)")
	authUserField := fs.String("auth-username-field", "", "login form username field name (default: username)")
	authPassField := fs.String("auth-password-field", "", "login form password field name (default: password)")
	snapshotPath := fs.String("snapshot", "", "cloud_account: inventory JSON (CloudQuery/Cartography export) → runs the AI Cloud Engineer dual-view")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *assetFlag == "" || *target == "" {
		return fmt.Errorf("--asset and --target are required")
	}
	at := types.AssetType(*assetFlag)
	if !at.Valid() {
		return fmt.Errorf("unknown asset type %q; valid: %v", *assetFlag, types.AllAssetTypes())
	}

	handler, err := handlerFor(at)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	scanID := newScanID()
	started := time.Now().UTC()

	spawnOpts := sandbox.SpawnOptions{Image: *image}
	switch at {
	case types.AssetRepository:
		// Bind-mount the source tree read-only at /workspace; the repo
		// Handler scans that path regardless of the host path.
		abs, aerr := filepath.Abs(*target)
		if aerr != nil {
			return fmt.Errorf("resolve repo path: %w", aerr)
		}
		if fi, serr := os.Stat(abs); serr != nil || !fi.IsDir() {
			return fmt.Errorf("repository target must be an existing directory: %s", *target)
		}
		spawnOpts.Mounts = []sandbox.Mount{{HostPath: abs, ContainerPath: repoasset.WorkspacePath}}
		fmt.Fprintf(os.Stderr, "[%s] mounting %s -> %s (ro)\n", scanID, abs, repoasset.WorkspacePath)
	case types.AssetCloudAccount:
		// Forward scoped, short-lived cloud credentials into the sandbox.
		spawnOpts.Env = cloudCredentialEnv()
		fmt.Fprintf(os.Stderr, "[%s] forwarding %d cloud credential vars\n", scanID, len(spawnOpts.Env))
	}

	fmt.Fprintf(os.Stderr, "[%s] spawning sandbox %s\n", scanID, *image)
	info, err := sandbox.Spawn(ctx, spawnOpts)
	if err != nil {
		return fmt.Errorf("spawn sandbox: %w", err)
	}
	defer func() {
		fmt.Fprintf(os.Stderr, "[%s] tearing down sandbox %s\n", scanID, shortID(info.ContainerID))
		_ = sandbox.Destroy(context.Background(), info)
	}()

	client := sandbox.NewClient(info)
	assetTarget := types.Asset{Type: at, Target: *target}

	// Wire authenticated-scan config when any auth flag is supplied. The
	// web Handler's PlanFanout only prepends seed_auth when target.Auth is
	// non-nil; the credentials never enter vulnerabilities.json (AuthConfig
	// is json:"-").
	if *authCookie != "" || *authLoginURL != "" {
		assetTarget.Auth = &types.AuthConfig{
			Cookie:        *authCookie,
			LoginURL:      *authLoginURL,
			Username:      *authUsername,
			Password:      *authPassword,
			UsernameField: *authUserField,
			PasswordField: *authPassField,
		}
		fmt.Fprintf(os.Stderr, "[%s] authenticated scan enabled (seed_auth)\n", scanID)
	}

	// Resolve the corpus pin BEFORE running anchors (CLAUDE.md §10): the
	// versions recorded here are what the scan ran against. Then write
	// the scan manifest so the reproducibility record survives even if
	// the scan crashes mid-way.
	corpus := resolveCorpus(ctx, client, info)
	if err := writeManifest(*outDir, scanID, assetTarget, started, info, corpus); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[%s] orchestrator running anchors against %s\n", scanID, *target)
	findings, fired, err := orchestrator.Run(ctx, assetTarget, handler, client)
	// A deadline (scan --timeout) is NOT fatal: the orchestrator returns the
	// findings that completed before the cutoff. Persist them, flagged
	// partial — a 0-finding timeout must be distinguishable from a clean
	// scan (the no-score-on-timeout trap). Any other error is fatal.
	partial, stopReason := false, ""
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			partial, stopReason = true, "timeout"
			fmt.Fprintf(os.Stderr, "[%s] scan hit the deadline — writing PARTIAL results\n", scanID)
		} else {
			return fmt.Errorf("orchestrator: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "[%s] anchors_fired=%v raw_findings=%d partial=%v\n", scanID, fired, len(findings), partial)

	// L1.5 enrichment runs host-side, after L1 emission (CLAUDE.md §11).
	// The raw findings feed the tracer; it produces the enriched view +
	// audit log. TSENGINE_L15_DISABLED=1 makes enriched == raw.
	disabled := os.Getenv("TSENGINE_L15_DISABLED") == "1"
	tr := tracer.New(disabled, hooks.DefaultPerFinding(), hooks.DefaultFinalize())
	for _, f := range findings {
		tr.Add(f)
	}
	tr.Finalize()
	fmt.Fprintf(os.Stderr, "[%s] L1.5 enriched=%d audit_entries=%d (l15_disabled=%v)\n",
		scanID, len(tr.Enriched()), len(tr.AuditLog()), disabled)

	// Child-asset pivot: a recon asset (domain) derives downstream targets
	// (subdomains → web/ip child assets) so webappsec spawns child scans
	// instead of re-enumerating (CLAUDE.md §5.1 / strix re-enumeration trap).
	var childAssets []types.ChildAsset
	if ce, ok := handler.(asset.ChildAssetExtractor); ok {
		childAssets = ce.ChildAssets(tr.Raw())
		if len(childAssets) > 0 {
			fmt.Fprintf(os.Stderr, "[%s] child assets discovered=%d\n", scanID, len(childAssets))
		}
	}

	scan := types.Scan{
		ScanID:           scanID,
		Asset:            assetTarget,
		StartedAt:        started,
		CompletedAt:      time.Now().UTC(),
		Engine:           types.Engine{Version: Version, SandboxImageDigest: info.ImageDigest},
		Corpus:           corpus,
		AnchorsFired:     fired,
		FindingsRaw:      tr.Raw(),
		FindingsEnriched: tr.Enriched(),
		L15AuditLog:      tr.AuditLog(),
		ChildAssets:      childAssets,
		Partial:          partial,
		StopReason:       stopReason,
	}

	// Dual-view: for a cloud_account scan with an inventory snapshot, attach the
	// AI Cloud Security Engineer's "engineer says" assessment alongside the
	// "tools say" findings_raw (ADR 0002). The attestation below covers both.
	attachCloudEngine(&scan, *snapshotPath, scanID)

	if err := signAndWrite(&scan, *outDir, scanID); err != nil {
		return err
	}
	fmt.Println(filepath.Join(*outDir, scanID, "vulnerabilities.json"))
	return nil
}

// --- replay ------------------------------------------------------

func runReplay(argv []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	scanID := fs.String("scan-id", "", "scan to extend")
	toolName := fs.String("tool", "", "tool to dispatch (anchor or registry)")
	target := fs.String("target", "", "override target (default: original scan's target)")
	runsDir := fs.String("runs", "runs", "directory holding scan outputs")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "fallback sandbox image when digest is not pullable")
	timeout := fs.Duration("timeout", 5*time.Minute, "replay timeout")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *scanID == "" || *toolName == "" {
		return fmt.Errorf("--scan-id and --tool are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	spawner := &replay.LiveSpawner{Image: *image}
	resp, err := replay.Replay(ctx, replay.Request{
		ScanID: *scanID,
		Tool:   *toolName,
		Target: *target,
	}, *runsDir, spawner)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[replay %s] %d findings\n", resp.ReplayID, len(resp.Findings))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

// attachCloudEngine runs the AI Cloud Security Engineer over a cloud_account
// scan's prowler findings + an inventory snapshot and attaches the dual-view
// assessment to the scan. No-op unless the asset is cloud_account and a
// snapshot path is given. Extracted for testability.
func attachCloudEngine(scan *types.Scan, snapshotPath, scanID string) {
	if scan.Asset.Type != types.AssetCloudAccount || snapshotPath == "" {
		return
	}
	snap, err := cloudgraph.LoadSnapshot(snapshotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] cloud-engine: snapshot load failed: %v\n", scanID, err)
		return
	}
	scan.AIAssessment = cloudengine.Assess(snap, scan.FindingsRaw, cloudengine.SnapshotOracle{}, cloudengine.Options{})
	fmt.Fprintf(os.Stderr, "[%s] AI cloud engineer: %d attack path(s), %d prowler finding(s) downgraded\n",
		scanID, len(scan.AIAssessment.Paths), len(scan.AIAssessment.Downgraded))
}

// --- cloud-assess ------------------------------------------------

// runCloudAssess runs the AI Cloud Security Engineer over an operator-provided
// inventory snapshot (a CloudQuery/Cartography export, or any inventory JSON)
// plus the optional prowler findings, and emits the dual-view assessment. No
// AWS, no model — the deterministic reasoning spine over the snapshot
// (ADR 0002, docs/design/ai-cloud-engineer.md). The live-AWS Analyzer and the
// LLM agent plug in on top of this same path.
func runCloudAssess(argv []string) error {
	fs := flag.NewFlagSet("cloud-assess", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "path to the inventory JSON (CloudQuery/Cartography export)")
	prowlerPath := fs.String("prowler", "", "optional path to prowler findings JSON (for corroborate/downgrade)")
	out := fs.String("out", "", "optional path to write the assessment JSON")
	llmFlag := fs.String("llm", "auto", "L2 LLM translator: auto (on if LLM_API_KEY set) | on | off")
	remediate := fs.Bool("remediate", false, "emit applyable, self-verified remediation artifacts (SCP / IAM Deny / SG revoke) for each attack path")
	maxHyp := fs.Int("max-hypotheses", 0, "engine worklist budget (0 = default 20); raise for accounts with many real attack paths")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("--snapshot is required")
	}

	snap, err := cloudgraph.LoadSnapshot(*snapshot)
	if err != nil {
		return err
	}

	var prowler []types.Finding
	if *prowlerPath != "" {
		b, rerr := os.ReadFile(*prowlerPath) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read prowler findings: %w", rerr)
		}
		if jerr := json.Unmarshal(b, &prowler); jerr != nil {
			return fmt.Errorf("parse prowler findings: %w", jerr)
		}
	}

	assessment := cloudengine.Assess(snap, prowler, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: *maxHyp})

	// L2 translator: refine the deterministic findings into developer-facing
	// prose + an executive summary (graceful — leaves the deterministic output
	// on any error or when no key is set).
	if *llmFlag != "off" {
		if g, ok := cloudengine.GeminiFromEnv(); ok {
			if terr := cloudengine.EnrichWithLLM(context.Background(), g, assessment); terr != nil {
				fmt.Fprintf(os.Stderr, "[cloud-assess] L2 translator skipped: %v\n", terr)
			}
		} else if *llmFlag == "on" {
			return fmt.Errorf("--llm on but LLM_API_KEY is not set")
		}
	}

	fmt.Print(cloudengine.RenderAssessment(assessment))

	if *remediate {
		fmt.Println()
		fmt.Print(cloudengine.RenderRemediations(cloudengine.GenerateRemediations(assessment)))
	}

	if *out != "" {
		b, merr := json.MarshalIndent(assessment, "", "  ")
		if merr != nil {
			return merr
		}
		if werr := os.WriteFile(*out, b, 0o600); werr != nil {
			return fmt.Errorf("write assessment: %w", werr)
		}
		fmt.Fprintf(os.Stderr, "[cloud-assess] wrote %s\n", *out)
	}
	return nil
}

// runCloudInvestigate runs the AI Cloud Security Engineer as an LLM AGENT (the
// VulnAgent shape, CLAUDE.md §10): the model drives, calling the cloud tool
// catalog (cloudgraph reachability, cloudiam effective-perms, the attack-path
// enumerator, the verified remediation generator) to access + assess the account
// and determine real attack paths. Needs LLM_API_KEY (the brain).
func runCloudInvestigate(argv []string) error {
	fs := flag.NewFlagSet("cloud-investigate", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "path to the inventory JSON (CloudQuery/Cartography export)")
	prowlerPath := fs.String("prowler", "", "optional path to prowler findings JSON")
	maxIters := fs.Int("max-iters", 28, "max tool-call turns before the loop is force-closed")
	maxHyp := fs.Int("max-hypotheses", 60, "worklist budget for the enumerate_attack_paths prepass tool")
	export := fs.String("export", "", "write each issue's verified remediation artifact to this dir (the applyable 'act' output)")
	ledgerOut := fs.String("ledger", "", "write a signed, replayable agent decision ledger (every thought/tool/observation step) to this JSON file")
	signKey := fs.String("sign-key", attest.DefaultKeyPath(), "ed25519 key to sign the ledger")
	signer := fs.String("signer", "", "human-readable signer id recorded in the ledger (default: derived from key)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("--snapshot is required")
	}
	snap, err := cloudgraph.LoadSnapshot(*snapshot)
	if err != nil {
		return err
	}
	var prowler []types.Finding
	if *prowlerPath != "" {
		b, rerr := os.ReadFile(*prowlerPath) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read prowler findings: %w", rerr)
		}
		if jerr := json.Unmarshal(b, &prowler); jerr != nil {
			return fmt.Errorf("parse prowler findings: %w", jerr)
		}
	}

	llm, ok := cloudengine.GeminiFromEnv()
	if !ok {
		return fmt.Errorf("cloud-investigate needs LLM_API_KEY (the agent's brain)")
	}
	var rec *ledger.Recorder
	if *ledgerOut != "" {
		rec = ledger.NewRecorder()
	}
	startedAt := time.Now().UTC()
	cc := &cloudagent.Context{Snap: snap, Prowler: prowler}
	rep, err := cloudagent.Investigate(context.Background(), llm, cc, cloudagent.Options{MaxIters: *maxIters, MaxHyp: *maxHyp, Ledger: rec})
	if err != nil {
		return err
	}
	fmt.Print(cloudagent.Render(rep))
	if *export != "" {
		n, eerr := cloudagent.ExportRemediations(rep, *export)
		if eerr != nil {
			return eerr
		}
		fmt.Fprintf(os.Stderr, "[cloud-investigate] exported %d applyable remediation artifact(s) → %s/\n", n, *export)
	}
	if *ledgerOut != "" {
		decisions := make([]ledger.Decision, 0, len(rep.Issues))
		for _, is := range rep.Issues {
			refs := is.Evidence
			if len(refs) == 0 {
				refs = is.Path
			}
			decisions = append(decisions, ledger.Decision{
				ID: is.ID, Kind: "attack_path", Severity: is.Severity, Refs: refs, Detail: is.Rationale,
			})
		}
		l := rec.Build(ledger.Meta{
			AgentKind: "cloudagent", Target: "cloud_account", Engine: "tsengine " + Version,
			Summary: rep.Summary, StartedAt: startedAt, CompletedAt: time.Now().UTC(), Decisions: decisions,
		})
		if werr := signAndWriteLedger(l, *signKey, *signer, *ledgerOut, "cloud-investigate"); werr != nil {
			return werr
		}
	}
	return nil
}

// runWebInvestigate points the LLM-as-brain offensive agent at one authorized
// live web/API target. The agent sends crafted requests, reads the engine's
// DETERMINISTIC indicators, and records only structurally-grounded findings
// (roadmap §1, docs/design/web-agent.md). The target's responses are untrusted
// data — a finding rides on an indicator, never on the model reading a page.
func runWebInvestigate(argv []string) error {
	fs := flag.NewFlagSet("web-investigate", flag.ContinueOnError)
	target := fs.String("target", "", "authorized target base URL (REQUIRED — you must own/have permission to test it)")
	seedCSV := fs.String("seed", "", "optional comma-separated seed routes from a prior scan (same host(s) as --target)")
	maxReq := fs.Int("max-requests", 120, "hard request budget (the runaway / do-no-harm guard)")
	maxIters := fs.Int("max-iters", 30, "max tool-call turns before the loop is force-closed")
	minInterval := fs.Duration("min-interval", 0, "throttle between requests (e.g. 200ms)")
	exportEvidence := fs.String("export-evidence", "", "write a signed, tamper-evident evidence bundle (the VAPT PoC deliverable) to this JSON file")
	ledgerOut := fs.String("ledger", "", "write a signed, replayable agent decision ledger (every thought/tool/observation step) to this JSON file")
	signKey := fs.String("sign-key", attest.DefaultKeyPath(), "ed25519 key to sign the evidence bundle / ledger")
	signer := fs.String("signer", "", "human-readable signer id recorded in the bundle (default: derived from key)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}

	var seed []string
	for _, s := range strings.Split(*seedCSV, ",") {
		if s = strings.TrimSpace(s); s != "" {
			seed = append(seed, s)
		}
	}

	llm, ok := cloudengine.GeminiFromEnv()
	if !ok {
		return fmt.Errorf("web-investigate needs LLM_API_KEY (the agent's brain)")
	}
	var rec *ledger.Recorder
	if *ledgerOut != "" {
		rec = ledger.NewRecorder()
	}
	startedAt := time.Now().UTC()
	cc := &webagent.Context{Target: *target}
	rep, err := webagent.Investigate(context.Background(), llm, cc, webagent.Options{
		MaxIters: *maxIters, MaxRequests: *maxReq, MinInterval: *minInterval, Seed: seed, Ledger: rec,
	})
	if err != nil {
		return err
	}
	fmt.Print(webagent.Render(rep))

	if *ledgerOut != "" {
		decisions := make([]ledger.Decision, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			decisions = append(decisions, ledger.Decision{
				ID: f.ID, Kind: f.Class, Severity: f.Severity, Refs: f.Evidence, Detail: f.Rationale,
			})
		}
		l := rec.Build(ledger.Meta{
			AgentKind: "webagent", Target: rep.Target, Engine: "tsengine " + Version,
			Summary: rep.Summary, StartedAt: startedAt, CompletedAt: time.Now().UTC(), Decisions: decisions,
		})
		if werr := signAndWriteLedger(l, *signKey, *signer, *ledgerOut, "web-investigate"); werr != nil {
			return werr
		}
	}

	if *exportEvidence != "" {
		priv, id, kerr := attest.LoadOrCreate(*signKey)
		if kerr != nil {
			return fmt.Errorf("evidence: load signing key: %w", kerr)
		}
		if *signer != "" {
			id = *signer
		}
		bundle := webagent.BuildEvidence(rep, cc, "tsengine "+Version)
		if serr := webagent.SignEvidence(bundle, id, priv, time.Now().UTC()); serr != nil {
			return serr
		}
		if werr := webagent.ExportEvidence(*exportEvidence, bundle); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[web-investigate] signed evidence bundle (%d finding(s), signer=%s) → %s\n",
			len(bundle.Findings), id, *exportEvidence)
	}
	return nil
}

// runWebVerify checks the ed25519 attestation on a web-agent evidence bundle.
// Without --pubkey it verifies against the local signing key's public half (the
// key that would have signed it on this machine); an auditor on another machine
// passes the distributed --pubkey.
func runWebVerify(argv []string) error {
	fs := flag.NewFlagSet("web-verify", flag.ContinueOnError)
	pubHex := fs.String("pubkey", "", "hex public key (default: local signing key's public half)")
	keyPath := fs.String("key", attest.DefaultKeyPath(), "local signing key (for the default pubkey)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: tsengine web-verify [--pubkey hex] <evidence.json>")
	}

	bundle, err := webagent.LoadEvidence(rest[0])
	if err != nil {
		return err
	}

	var pub ed25519.PublicKey
	if *pubHex != "" {
		if pub, err = attest.ParsePublicKeyHex(*pubHex); err != nil {
			return fmt.Errorf("parse --pubkey: %w", err)
		}
	} else {
		priv, _, kerr := attest.LoadOrCreate(*keyPath)
		if kerr != nil {
			return fmt.Errorf("load local key: %w", kerr)
		}
		pub = priv.Public().(ed25519.PublicKey)
	}

	if err := webagent.VerifyEvidence(bundle, pub); err != nil {
		return err
	}
	fmt.Printf("OK — evidence bundle verified (signer=%s, signed_at=%s)\n",
		bundle.Attestation.Signer, bundle.Attestation.SignedAt.Format(time.RFC3339))
	fmt.Printf("target: %s   findings: %d\n", bundle.Target, len(bundle.Findings))
	for _, f := range bundle.Findings {
		tick := " "
		if f.Verified {
			tick = "✓"
		}
		fmt.Printf("  [%s] %s  class=%s  verified=%s  proving_turns=%d\n",
			f.ID, f.Route, f.Class, tick, len(f.ProvingTurns))
	}
	return nil
}

// runLLMRedteam runs the agentic LLM red-team service (roadmap §2). With --bench
// it generates an emulated population of target LLMs (vulnerable + hardened decoys)
// and runs the deterministic attacker against all of them — a self-contained,
// no-API-key demonstration that the verifier's grounding cracks every vulnerable
// target while flagging zero hardened ones. A live HTTP-target adapter is the next
// rung; the attacker loop already accepts a real cloudengine.LLM brain.
func runLLMRedteam(argv []string) error {
	fs := flag.NewFlagSet("llm-redteam", flag.ContinueOnError)
	bench := fs.Bool("bench", false, "run against an emulated population (vulnerable + hardened targets)")
	seed := fs.Int64("seed", 1, "generation seed")
	n := fs.Int("n", 14, "number of targets in the population")
	hardenedFrac := fs.Float64("hardened-frac", 0.4, "fraction of targets that are hardened decoys")
	ledgerOut := fs.String("ledger", "", "write a signed, replayable agent decision ledger for one engagement to this JSON file")
	signKey := fs.String("sign-key", attest.DefaultKeyPath(), "ed25519 key to sign the ledger")
	signer := fs.String("signer", "", "human-readable signer id recorded in the ledger (default: derived from key)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if !*bench {
		return fmt.Errorf("only --bench (emulated population) is supported today; a live --target HTTP adapter is the next rung")
	}

	rg := llmredteam.Generate(*seed, llmredteam.Opts{N: *n, HardenedFrac: *hardenedFrac})
	sc, reports, err := llmredteam.ScorePopulation(context.Background(), nil, rg, llmredteam.Options{})
	if err != nil {
		return err
	}
	fmt.Print(llmredteam.RenderScore(sc))
	for i, spec := range rg.Manifest.Targets {
		rep := reports[i]
		status := "hardened"
		if spec.Vulnerable {
			status = "vulnerable(" + spec.Weakness + ")"
		}
		mark := "·"
		if len(rep.Breaches) > 0 {
			mark = "BREACHED"
		}
		fmt.Printf("  %-9s %-22s %s  (%d breach, %d prompts)\n", spec.ID, status, mark, len(rep.Breaches), rep.Turns)
	}

	// --ledger: re-run ONE engagement (the first vulnerable target) with a recorder
	// attached, then sign + export the replayable decision ledger. Deterministic
	// attacker (no API key) → a self-contained, reproducible ledger demo.
	if *ledgerOut != "" {
		var pick string
		for _, spec := range rg.Manifest.Targets {
			if spec.Vulnerable {
				pick = spec.ID
				break
			}
		}
		if pick == "" {
			return fmt.Errorf("ledger: no vulnerable target in the population to record")
		}
		rec := ledger.NewRecorder()
		startedAt := time.Now().UTC()
		rep, rerr := llmredteam.RunEngagement(context.Background(), nil,
			rg.Target(pick), rg.Engagement(pick), llmredteam.Options{Ledger: rec})
		if rerr != nil {
			return rerr
		}
		decisions := make([]ledger.Decision, 0, len(rep.Breaches))
		for _, b := range rep.Breaches {
			decisions = append(decisions, ledger.Decision{
				ID: b.ID, Kind: b.Class, Severity: b.Severity, Refs: b.Evidence, Detail: b.Rationale,
			})
		}
		l := rec.Build(ledger.Meta{
			EngagementID: pick, AgentKind: "llmredteam", Target: rep.Engagement, Engine: "tsengine " + Version,
			Summary: rep.Summary, StartedAt: startedAt, CompletedAt: time.Now().UTC(), Decisions: decisions,
		})
		if werr := signAndWriteLedger(l, *signKey, *signer, *ledgerOut, "llm-redteam"); werr != nil {
			return werr
		}
	}
	return nil
}

// runReport renders a branded VAPT report (Markdown or self-contained HTML) from
// an engine output — an L1 dashboard vulnerabilities.json or a web-agent signed
// evidence bundle (auto-detected). The sellable deliverable (roadmap §4 / §7-#1).
func runReport(argv []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	in := fs.String("in", "", "input JSON: a vulnerabilities.json scan OR a web-agent evidence bundle (REQUIRED)")
	format := fs.String("format", "md", "output format: md | html")
	out := fs.String("out", "", "output file (default: stdout)")
	org := fs.String("org", "", "client/org name printed on the report")
	title := fs.String("title", "", "override the report title")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	data, err := os.ReadFile(*in) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	rep, err := buildReport(data)
	if err != nil {
		return err
	}
	if *org != "" {
		rep.Org = *org
	}
	if *title != "" {
		rep.Title = *title
	}

	var rendered string
	switch *format {
	case "md", "markdown":
		rendered = report.Markdown(rep)
	case "html":
		rendered = report.HTML(rep)
	default:
		return fmt.Errorf("unknown --format %q (want md or html)", *format)
	}

	if *out == "" {
		fmt.Print(rendered)
		return nil
	}
	if err := os.WriteFile(*out, []byte(rendered), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[report] %d finding(s) → %s (%s)\n", len(rep.Findings), *out, *format)
	return nil
}

// buildReport auto-detects the input kind (scan vs web-evidence bundle) and adapts.
func buildReport(data []byte) (*report.Report, error) {
	now := time.Now().UTC()
	var scan types.Scan
	if err := json.Unmarshal(data, &scan); err == nil && scan.ScanID != "" {
		return report.FromScan(scan, now), nil
	}
	var bundle webagent.EvidenceBundle
	if err := json.Unmarshal(data, &bundle); err == nil && bundle.Target != "" && len(bundle.Findings) >= 0 && bundle.Attestation != nil {
		return report.FromWebEvidence(&bundle, now), nil
	}
	// last resort: a scan without a scan_id (e.g. hand-authored) still has an asset
	if scan.Asset.Target != "" {
		return report.FromScan(scan, now), nil
	}
	return nil, fmt.Errorf("could not recognize input as a vulnerabilities.json scan or a web-agent evidence bundle")
}

// runFindings is the durable findings DB CLI (roadmap §4 / §7-#1): ingest scans /
// evidence bundles, list with filters + SLA, and transition lifecycle state.
func runFindings(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("usage: tsengine findings <ingest|list|set> --db <file> [...]")
	}
	switch argv[0] {
	case "ingest":
		return runFindingsIngest(argv[1:])
	case "list":
		return runFindingsList(argv[1:])
	case "set":
		return runFindingsSet(argv[1:])
	default:
		return fmt.Errorf("unknown findings subcommand %q (want ingest|list|set)", argv[0])
	}
}

func runFindingsIngest(argv []string) error {
	fs := flag.NewFlagSet("findings ingest", flag.ContinueOnError)
	db := fs.String("db", "findings.json", "path to the findings database")
	in := fs.String("in", "", "input: vulnerabilities.json scan OR web-agent evidence bundle (REQUIRED)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	store, err := findingstore.Load(*db)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	now := time.Now().UTC()

	var newN, reopenN, fixedN int
	var scan types.Scan
	if json.Unmarshal(data, &scan) == nil && (scan.ScanID != "" || scan.Asset.Target != "") {
		newN, reopenN, fixedN = store.IngestScan(scan, now)
	} else {
		var bundle webagent.EvidenceBundle
		if json.Unmarshal(data, &bundle) != nil || bundle.Target == "" {
			return fmt.Errorf("input is neither a vulnerabilities.json scan nor a web-agent evidence bundle")
		}
		newN, reopenN, fixedN = store.IngestWebEvidence(&bundle, now)
	}
	if err := store.Save(*db); err != nil {
		return err
	}
	fmt.Printf("ingested: %d new, %d reopened, %d auto-fixed → %s (%d tracked)\n", newN, reopenN, fixedN, *db, len(store.Records))
	return nil
}

func runFindingsList(argv []string) error {
	fs := flag.NewFlagSet("findings list", flag.ContinueOnError)
	db := fs.String("db", "findings.json", "path to the findings database")
	status := fs.String("status", "", "filter by status (open|fixed|verified|closed|reopened|accepted_risk)")
	severity := fs.String("severity", "", "filter by severity")
	openOnly := fs.Bool("open", false, "only open + reopened")
	overdue := fs.Bool("overdue", false, "only SLA-overdue (implies open)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	store, err := findingstore.Load(*db)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	var recs []*findingstore.Record
	if *overdue {
		recs = store.Overdue(now)
	} else {
		recs = store.List(findingstore.Filter{Status: findingstore.Status(*status), Severity: *severity, OpenOnly: *openOnly})
	}

	c := store.Counts()
	fmt.Printf("findings DB: %s  (open %d, reopened %d, fixed %d, verified %d, closed %d) — %d overdue\n",
		*db, c[findingstore.StatusOpen], c[findingstore.StatusReopened], c[findingstore.StatusFixed],
		c[findingstore.StatusVerified], c[findingstore.StatusClosed], len(store.Overdue(now)))
	if len(recs) == 0 {
		fmt.Println("(no matching findings)")
		return nil
	}
	for _, r := range recs {
		due := ""
		if (r.Status == findingstore.StatusOpen || r.Status == findingstore.StatusReopened) && now.After(r.DueAt) {
			due = "  ⚠ OVERDUE"
		}
		owner := ""
		if r.Owner != "" {
			owner = "  @" + r.Owner
		}
		fmt.Printf("  %s  %-8s %-9s %-9s %s  <%s>%s%s\n",
			r.ID, strings.ToUpper(r.Severity), r.Status, age(now.Sub(r.FirstSeen)), r.Title, r.Endpoint, owner, due)
	}
	return nil
}

func runFindingsSet(argv []string) error {
	fs := flag.NewFlagSet("findings set", flag.ContinueOnError)
	db := fs.String("db", "findings.json", "path to the findings database")
	id := fs.String("id", "", "finding id (F-...) (REQUIRED)")
	status := fs.String("status", "", "new status")
	owner := fs.String("owner", "", "assign owner")
	note := fs.String("note", "", "transition note")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	store, err := findingstore.Load(*db)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	did := false
	if *status != "" {
		if !store.Transition(*id, findingstore.Status(*status), *note, now) {
			return fmt.Errorf("unknown finding id %q", *id)
		}
		did = true
	}
	if *owner != "" {
		if !store.Assign(*id, *owner) {
			return fmt.Errorf("unknown finding id %q", *id)
		}
		did = true
	}
	if !did {
		return fmt.Errorf("nothing to do: pass --status and/or --owner")
	}
	if err := store.Save(*db); err != nil {
		return err
	}
	fmt.Printf("updated %s → status=%s owner=%s\n", *id, store.Records[*id].Status, store.Records[*id].Owner)
	return nil
}

func age(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days <= 0 {
		return "today"
	}
	return fmt.Sprintf("%dd", days)
}

// runServe starts the long-running tsengine HTTP service (CLAUDE.md §9): the
// tool-replay API behind bearer auth + liveness/readiness/version probes. This is
// the deployable surface webappsec talks to. It blocks until SIGINT/SIGTERM, then
// drains gracefully.
func runServe(argv []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", envOr("TSENGINE_ADDR", ":8080"), "listen address")
	runsDir := fs.String("runs", envOr("TSENGINE_RUNS_DIR", "runs"), "directory holding scan outputs (for /replay)")
	token := fs.String("token", os.Getenv("TSENGINE_API_TOKEN"), "bearer token for protected endpoints (or TSENGINE_API_TOKEN)")
	image := fs.String("image", os.Getenv("TSENGINE_SANDBOX_IMAGE"), "sandbox image ref/digest for replay dispatch")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.Run(ctx, server.Config{
		Addr:    *addr,
		Token:   *token,
		RunsDir: *runsDir,
		Version: Version,
	}, &replay.LiveSpawner{Image: *image})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// runServeBench load-tests a RUNNING tsengine service: throughput + latency
// percentiles AND the auth-correctness invariant under concurrency (every
// unauthenticated /replay rejected, every authenticated one admitted — zero
// violations). Exits non-zero if the invariant breaks or transport errors occur,
// so it doubles as a pre-deploy gate.
func runServeBench(argv []string) error {
	fs := flag.NewFlagSet("serve-bench", flag.ContinueOnError)
	target := fs.String("target", "http://127.0.0.1:8080", "base URL of a running tsengine service")
	token := fs.String("token", os.Getenv("TSENGINE_API_TOKEN"), "the service's API token (or TSENGINE_API_TOKEN)")
	requests := fs.Int("requests", 6000, "total requests (ignored if --duration > 0)")
	concurrency := fs.Int("concurrency", 48, "parallel workers")
	duration := fs.Duration("duration", 0, "run for this long instead of a fixed request count")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("--token (or TSENGINE_API_TOKEN) is required")
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256, IdleConnTimeout: 30 * time.Second},
	}
	res, err := loadbench.Run(context.Background(), loadbench.Config{
		BaseURL: *target, Token: *token, Requests: *requests, Duration: *duration,
		Concurrency: *concurrency, Client: client,
	})
	if err != nil {
		return err
	}
	fmt.Print(loadbench.Render(res))
	if !res.Pass {
		return fmt.Errorf("benchmark FAILED: %d auth violations, %d transport errors", res.AuthViolations, res.Errors)
	}
	return nil
}

// runReachability answers the SCA-triage question that separates noise from a real
// finding: a scanner says a dependency has a vulnerable function — does THIS code
// actually call it, from an application entrypoint? Closes the Validation hole for
// dependency findings (roadmap §3). Go-first; verdict cites the call path (grounded).
func runReachability(argv []string) error {
	fs := flag.NewFlagSet("reachability", flag.ContinueOnError)
	repo := fs.String("repo", ".", "path to the source repository to analyze")
	pkg := fs.String("package", "", "vulnerable dependency import/module path (single-query mode)")
	sca := fs.String("sca", "", "JSON file of SCA findings to triage (batch mode): [{id,cve,package,symbols,severity}]")
	var symbols multiFlag
	fs.Var(&symbols, "symbol", "vulnerable symbol (repeatable; empty = any symbol from the package)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *pkg == "" && *sca == "" {
		return fmt.Errorf("provide --package <path> (single query) or --sca <findings.json> (batch)")
	}

	g, err := reachability.Extract(*repo)
	if err != nil {
		return fmt.Errorf("extract call graph: %w", err)
	}

	if *sca != "" {
		data, rerr := os.ReadFile(*sca) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read sca findings: %w", rerr)
		}
		var findings []reachability.SCAFinding
		if jerr := json.Unmarshal(data, &findings); jerr != nil {
			return fmt.Errorf("parse sca findings: %w", jerr)
		}
		results := reachability.TriageSCA(g, findings)
		if *jsonOut {
			b, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Print(reachability.Render(results))
		// non-zero exit if any reachable (useful as a CI gate)
		for _, r := range results {
			if r.Priority == "reachable" {
				os.Exit(3)
			}
		}
		return nil
	}

	v := reachability.Analyze(g, *pkg, symbols)
	if *jsonOut {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if v.Reachable {
		fmt.Printf("REACHABLE: %s is called from an application entrypoint.\n  path: %s\n", *pkg, strings.Join(v.Path, " → "))
		os.Exit(3)
	}
	switch {
	case !v.Imported:
		fmt.Printf("NOT REACHABLE: %s — the vulnerable symbol is never called in this codebase (present-but-unused).\n", *pkg)
	default:
		fmt.Printf("NOT REACHABLE: %s is called only from non-entrypoint (dead) code: %s\n", *pkg, strings.Join(v.DirectHitters, ", "))
	}
	return nil
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error {
	*m = append(*m, s)
	return nil
}

// runGate is the CI/CD security gate (roadmap §1, Shift-Left): evaluate the
// engine's findings (an L1 scan, a web-exploit evidence bundle, and/or SCA
// reachability) against a policy and exit non-zero to block a merge. Gates on what
// the engine PROVED (verified exploit, reachable dependency CVE), supports a
// baseline (fail on NEW risk only) + waivers.
func runGate(argv []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	in := fs.String("in", "", "findings input: vulnerabilities.json scan OR a web-agent evidence bundle")
	scaPath := fs.String("sca", "", "SCA findings JSON to reachability-triage (needs --repo)")
	repo := fs.String("repo", ".", "repo for --sca reachability")
	policyPath := fs.String("policy", "", "policy JSON (gate.Policy); flags override its fields")
	failOn := fs.String("fail-on", "high", "fail if any finding severity ≥ this (critical|high|medium|low; empty disables)")
	failVerified := fs.Bool("fail-on-verified", true, "fail on any verified/proven-exploitable finding")
	failReachable := fs.Bool("fail-on-reachable", true, "fail on any reachable dependency CVE")
	maxNew := fs.Int("max-new", -1, "fail if NEW findings (vs baseline) exceed this; <0 disables")
	newOnly := fs.Bool("new-only", false, "only gate on findings absent from the baseline")
	baselinePath := fs.String("baseline", "", "baseline fingerprints JSON ([\"g-...\"]) — accepted prior findings")
	saveBaseline := fs.String("save-baseline", "", "write the current findings' fingerprints to this file")
	format := fs.String("format", "text", "output format: text | json | github")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *in == "" && *scaPath == "" {
		return fmt.Errorf("provide --in <scan|evidence.json> and/or --sca <findings.json>")
	}

	var findings []gate.Finding
	if *in != "" {
		data, rerr := os.ReadFile(*in) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read --in: %w", rerr)
		}
		rep, berr := buildReport(data)
		if berr != nil {
			return berr
		}
		findings = append(findings, gate.FromReport(rep)...)
	}
	if *scaPath != "" {
		g, gerr := reachability.Extract(*repo)
		if gerr != nil {
			return fmt.Errorf("reachability extract: %w", gerr)
		}
		data, rerr := os.ReadFile(*scaPath) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read --sca: %w", rerr)
		}
		var sca []reachability.SCAFinding
		if jerr := json.Unmarshal(data, &sca); jerr != nil {
			return fmt.Errorf("parse --sca: %w", jerr)
		}
		findings = append(findings, gate.FromReachability(reachability.TriageSCA(g, sca))...)
	}

	// policy: start from the JSON file (or defaults), then let explicitly-set flags win.
	policy := gate.DefaultPolicy()
	if *policyPath != "" {
		data, rerr := os.ReadFile(*policyPath) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read --policy: %w", rerr)
		}
		if jerr := json.Unmarshal(data, &policy); jerr != nil {
			return fmt.Errorf("parse --policy: %w", jerr)
		}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "fail-on":
			policy.FailOnSeverity = *failOn
		case "fail-on-verified":
			policy.FailOnVerified = *failVerified
		case "fail-on-reachable":
			policy.FailOnReachableSCA = *failReachable
		case "max-new":
			policy.MaxNewFindings = *maxNew
		case "new-only":
			policy.NewOnly = *newOnly
		}
	})

	var baseline map[string]bool
	if *baselinePath != "" {
		data, rerr := os.ReadFile(*baselinePath) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read --baseline: %w", rerr)
		}
		var fps []string
		if jerr := json.Unmarshal(data, &fps); jerr != nil {
			return fmt.Errorf("parse --baseline: %w", jerr)
		}
		baseline = map[string]bool{}
		for _, fp := range fps {
			baseline[fp] = true
		}
	}

	res := gate.Evaluate(findings, policy, baseline, time.Now().UTC())

	if *saveBaseline != "" {
		b, _ := json.MarshalIndent(gate.Fingerprints(findings), "", "  ")
		if werr := os.WriteFile(*saveBaseline, append(b, '\n'), 0o600); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[gate] baseline (%d fingerprints) → %s\n", len(findings), *saveBaseline)
	}

	switch *format {
	case "json":
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	case "github":
		fmt.Print(gate.RenderGitHub(res))
	default:
		fmt.Print(gate.Render(res))
	}
	if !res.Passed {
		os.Exit(1)
	}
	return nil
}

// runImport normalizes another scanner's output (SARIF / Snyk / GitHub Dependabot)
// into the engine's contracts so it flows through report / findings DB / gate /
// reachability (roadmap §3). The multiplier: a customer's existing Snyk/Semgrep/
// CodeQL results get the grounding + gate treatment for free.
func runImport(argv []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	in := fs.String("in", "", "scanner output file (SARIF / Snyk JSON / Dependabot alerts JSON) (REQUIRED)")
	format := fs.String("format", "auto", "input format: auto | sarif | snyk | dependabot")
	as := fs.String("as", "scan", "output shape: scan (vulnerabilities.json) | sca (reachability findings)")
	target := fs.String("target", "", "asset/project name for the emitted scan")
	out := fs.String("out", "", "output file (default: stdout)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	data, err := os.ReadFile(*in) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	var payload any
	switch *as {
	case "sca":
		sca, ierr := importers.ImportSCA(data, importers.Format(*format))
		if ierr != nil {
			return ierr
		}
		payload = sca
		fmt.Fprintf(os.Stderr, "[import] %d SCA finding(s) (feed to: tsengine reachability --sca / gate --sca)\n", len(sca))
	case "scan", "":
		scan, ierr := importers.Import(data, importers.Format(*format), *target, time.Now().UTC())
		if ierr != nil {
			return ierr
		}
		payload = scan
		fmt.Fprintf(os.Stderr, "[import] %d finding(s) from %s → scan (feed to: tsengine report / findings ingest / gate --in)\n",
			len(scan.FindingsEnriched), strings.Join(scan.AnchorsFired, ","))
	default:
		return fmt.Errorf("unknown --as %q (want scan or sca)", *as)
	}

	b, _ := json.MarshalIndent(payload, "", "  ")
	if *out == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(*out, append(b, '\n'), 0o600)
}

// runCorrelate builds cross-asset attack chains across multiple scans — the
// Prioritization layer (roadmap §3/§4): a finding on one asset that bridges, via a
// concrete shared identifier (a leaked AWS key, an ARN, a host), to a crown jewel on
// another asset. Grounded: every hop cites the identifier that links the two.
func runCorrelate(argv []string) error {
	fs := flag.NewFlagSet("correlate", flag.ContinueOnError)
	var ins multiFlag
	fs.Var(&ins, "in", "a vulnerabilities.json scan (repeat --in for each asset's scan)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if len(ins) < 2 {
		return fmt.Errorf("provide at least two --in <scan.json> files (one per asset) to correlate across")
	}

	var assets []correlate.Asset
	for _, p := range ins {
		data, rerr := os.ReadFile(p) //nolint:gosec // operator-provided path
		if rerr != nil {
			return fmt.Errorf("read %s: %w", p, rerr)
		}
		var scan types.Scan
		if jerr := json.Unmarshal(data, &scan); jerr != nil {
			return fmt.Errorf("parse %s: %w", p, jerr)
		}
		assets = append(assets, correlate.FromScan(scan))
	}

	chains := correlate.Correlate(assets)
	if *jsonOut {
		b, _ := json.MarshalIndent(chains, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(correlate.Render(chains))
	return nil
}

// runExport is the OUTBOUND handoff (roadmap §9): emit tsengine's proven findings
// into the systems a customer already runs — SARIF (→ GitHub code-scanning / any
// SARIF consumer, inline on the PR) or a signed finding/case webhook (→ SIEM / SOC /
// AI-SOC / ticketing). The mirror of `tsengine import`.
func runExport(argv []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	in := fs.String("in", "", "findings input: a vulnerabilities.json scan OR a web-agent evidence bundle (REQUIRED)")
	format := fs.String("format", "sarif", "output format: sarif | json (the webhook event payload)")
	out := fs.String("out", "", "output file (default: stdout)")
	webhook := fs.String("webhook", "", "POST the finding/case event to this URL (instead of/with file output)")
	webhookToken := fs.String("webhook-token", os.Getenv("TSENGINE_WEBHOOK_TOKEN"), "bearer token for the webhook")
	hmacSecret := fs.String("hmac-secret", os.Getenv("TSENGINE_WEBHOOK_HMAC"), "HMAC-SHA256 secret to sign the webhook body")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	data, err := os.ReadFile(*in) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	rep, err := buildReport(data)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	// webhook path: POST the normalized event.
	if *webhook != "" {
		ev := exporter.EventFromReport(rep, now)
		code, eerr := exporter.Emit(context.Background(), ev, exporter.EmitOptions{
			URL: *webhook, Token: *webhookToken, HMACSecret: *hmacSecret,
		})
		if eerr != nil {
			return eerr
		}
		fmt.Fprintf(os.Stderr, "[export] POSTed %d finding(s) → %s (HTTP %d)%s\n",
			len(ev.Findings), *webhook, code, signedNote(*hmacSecret))
		return nil
	}

	// file/stdout path.
	var rendered []byte
	switch *format {
	case "sarif":
		rendered, err = exporter.ToSARIF(rep)
	case "json":
		ev := exporter.EventFromReport(rep, now)
		rendered, err = json.MarshalIndent(ev, "", "  ")
	default:
		return fmt.Errorf("unknown --format %q (want sarif or json)", *format)
	}
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(rendered))
		return nil
	}
	if werr := os.WriteFile(*out, append(rendered, '\n'), 0o600); werr != nil {
		return werr
	}
	fmt.Fprintf(os.Stderr, "[export] %d finding(s) → %s (%s)\n", len(rep.Findings), *out, *format)
	return nil
}

func signedNote(secret string) string {
	if secret != "" {
		return " [HMAC-signed]"
	}
	return ""
}

// --- ledger (replayable agent decision ledger, roadmap §9) -------

// signAndWriteLedger signs a built ledger with the local ed25519 key and writes it.
// Shared by web-investigate / cloud-investigate / llm-redteam --ledger.
func signAndWriteLedger(l *ledger.Ledger, keyPath, signerOverride, out, tag string) error {
	priv, id, err := attest.LoadOrCreate(keyPath)
	if err != nil {
		return fmt.Errorf("ledger: load signing key: %w", err)
	}
	if signerOverride != "" {
		id = signerOverride
	}
	if err := ledger.Sign(l, id, priv, time.Now().UTC()); err != nil {
		return err
	}
	if err := ledger.Export(out, l); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[%s] signed agent decision ledger (%d step(s), %d decision(s), signer=%s) → %s\n",
		tag, len(l.Steps), len(l.Decisions), id, out)
	return nil
}

// runLedger handles `tsengine ledger <verify|replay|show> <ledger.json>` — the
// auditor's side of the replayable agent decision ledger. verify checks the ed25519
// attestation (the record was not altered after signing); replay reconstructs the
// thought→tool→observation trail; show prints a one-line summary.
func runLedger(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("usage: tsengine ledger <verify|replay|show> [flags] <ledger.json>")
	}
	sub, rest := argv[0], argv[1:]
	switch sub {
	case "verify":
		fs := flag.NewFlagSet("ledger verify", flag.ContinueOnError)
		pubHex := fs.String("pubkey", "", "hex public key (default: local signing key's public half)")
		keyPath := fs.String("key", attest.DefaultKeyPath(), "local signing key (for the default pubkey)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		args := fs.Args()
		if len(args) != 1 {
			return fmt.Errorf("usage: tsengine ledger verify [--pubkey hex] <ledger.json>")
		}
		l, err := ledger.Load(args[0])
		if err != nil {
			return err
		}
		pub, err := resolvePubkey(*pubHex, *keyPath)
		if err != nil {
			return err
		}
		if err := ledger.Verify(l, pub); err != nil {
			return err
		}
		fmt.Printf("OK — agent decision ledger verified (signer=%s, signed_at=%s)\n",
			l.Attestation.Signer, l.Attestation.SignedAt.Format(time.RFC3339))
		fmt.Printf("agent=%s  target=%s  steps=%d  decisions=%d\n",
			l.AgentKind, l.Target, len(l.Steps), len(l.Decisions))
		return nil

	case "replay":
		fs := flag.NewFlagSet("ledger replay", flag.ContinueOnError)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		args := fs.Args()
		if len(args) != 1 {
			return fmt.Errorf("usage: tsengine ledger replay <ledger.json>")
		}
		l, err := ledger.Load(args[0])
		if err != nil {
			return err
		}
		fmt.Printf("agent decision ledger — %s vs %s  (%d steps, %d grounded decisions)\n",
			l.AgentKind, nzStr(l.Target, "—"), len(l.Steps), len(l.Decisions))
		if l.Attestation != nil {
			fmt.Printf("signer=%s  signed_at=%s\n\n", l.Attestation.Signer, l.Attestation.SignedAt.Format(time.RFC3339))
		}
		for _, line := range ledger.Replay(l) {
			fmt.Println(line)
		}
		return nil

	case "show":
		fs := flag.NewFlagSet("ledger show", flag.ContinueOnError)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		args := fs.Args()
		if len(args) != 1 {
			return fmt.Errorf("usage: tsengine ledger show <ledger.json>")
		}
		l, err := ledger.Load(args[0])
		if err != nil {
			return err
		}
		signer := "unsigned"
		if l.Attestation != nil {
			signer = l.Attestation.Signer
		}
		fmt.Printf("%s  agent=%s  target=%s  steps=%d  decisions=%d  signer=%s\n",
			nzStr(l.EngagementID, "(ledger)"), l.AgentKind, nzStr(l.Target, "—"),
			len(l.Steps), len(l.Decisions), signer)
		return nil

	default:
		return fmt.Errorf("unknown ledger subcommand %q (want verify|replay|show)", sub)
	}
}

// resolvePubkey returns the public key for verification: an explicit hex key, else
// the public half of the local signing key.
func resolvePubkey(pubHex, keyPath string) (ed25519.PublicKey, error) {
	if pubHex != "" {
		return attest.ParsePublicKeyHex(pubHex)
	}
	priv, _, err := attest.LoadOrCreate(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load local key: %w", err)
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func nzStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// --- pubkey ------------------------------------------------------

// runPubkey prints the hex-encoded public signing key + its signer id,
// for distribution to webappsec / auditors who verify attestations.
func runPubkey(argv []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	keyPath := fs.String("key", attest.DefaultKeyPath(), "signing key path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	priv, signer, err := attest.LoadOrCreate(*keyPath)
	if err != nil {
		return err
	}
	fmt.Printf("signer:     %s\n", signer)
	fmt.Printf("public_key: %s\n", attest.PublicKeyHex(priv))
	fmt.Printf("key_path:   %s\n", *keyPath)
	return nil
}

// --- verify ------------------------------------------------------

// runVerify checks a scan's attestation. Without --pubkey it verifies
// against the local default key's public half (the key that would have
// signed it on this machine); auditors on another machine pass the
// distributed --pubkey.
func runVerify(argv []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubHex := fs.String("pubkey", "", "hex public key (default: local signing key's public half)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: tsengine verify [--pubkey hex] <vulnerabilities.json>")
	}

	data, err := os.ReadFile(rest[0]) //nolint:gosec // operator-provided path
	if err != nil {
		return fmt.Errorf("read scan: %w", err)
	}
	var scan types.Scan
	if err := json.Unmarshal(data, &scan); err != nil {
		return fmt.Errorf("decode scan: %w", err)
	}

	var pub ed25519.PublicKey
	if *pubHex != "" {
		pub, err = attest.ParsePublicKeyHex(*pubHex)
		if err != nil {
			return err
		}
	} else {
		priv, _, lerr := attest.LoadOrCreate(attest.DefaultKeyPath())
		if lerr != nil {
			return lerr
		}
		pub = priv.Public().(ed25519.PublicKey)
	}

	if err := dashboard.Verify(scan, pub); err != nil {
		return err
	}
	fmt.Printf("OK: attestation valid (scan %s, signer %s)\n", scan.ScanID, scan.Attestation.Signer)
	return nil
}

// --- shared ------------------------------------------------------

// handlerFor resolves the Handler implementation for an asset type.
// All 7 asset types route to a Handler — some (repository, cloud_account)
// are skeleton Handlers in Phase 3 that produce an empty (valid) scan
// until their anchor wrappers land in Phase 3.x.
func handlerFor(at types.AssetType) (asset.Handler, error) {
	switch at {
	case types.AssetWebApplication:
		return webasset.NewHandler(), nil
	case types.AssetAPI:
		return apiasset.NewHandler(), nil
	case types.AssetRepository:
		return repoasset.NewHandler(), nil
	case types.AssetContainerImage:
		return containerasset.NewHandler(), nil
	case types.AssetIPAddress:
		return ipasset.NewHandler(), nil
	case types.AssetDomain:
		return domainasset.NewHandler(), nil
	case types.AssetCloudAccount:
		return cloudasset.NewHandler(), nil
	default:
		return nil, fmt.Errorf("unhandled asset type %q", at)
	}
}

// resolveCorpus pins the signature/template/DB versions this scan ran
// against. Sandbox-queryable versions (nuclei templates, trivy DB, tool
// versions) come from the /corpus endpoint; the embedded L1.5 corpora
// (threat-intel, compliance) come from version constants. Best-effort —
// a sandbox that can't report a version just leaves it blank.
func resolveCorpus(ctx context.Context, client *sandbox.Client, info *sandbox.Info) types.Corpus {
	tiVersion, kevAsOf, epssAsOf := hooks.ThreatIntelCorpusInfo()
	corpus := types.Corpus{
		ComplianceCorpus: hooks.ComplianceCorpusVersion,
		KEVSnapshot:      kevAsOf,
		EPSSSnapshot:     epssAsOf,
		Custom:           map[string]string{},
	}
	ci, err := client.Corpus(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[corpus] could not resolve sandbox versions: %v\n", err)
		return corpus
	}
	corpus.Nuclei = ci.NucleiTemplates
	if ci.TrivyDBUpdated != "" {
		if t, perr := time.Parse(time.RFC3339, ci.TrivyDBUpdated); perr == nil {
			corpus.TrivyDB = &t
		}
	}
	for tool, ver := range ci.ToolVersions {
		corpus.Custom[tool] = ver
	}
	corpus.Custom["threat_intel_corpus"] = tiVersion
	return corpus
}

// scanManifest is the reproducibility pin written at scan START — before
// any finding. It survives a mid-scan crash so a re-run can reconstruct
// the exact corpus + image (CLAUDE.md §10).
type scanManifest struct {
	ScanID             string       `json:"scan_id"`
	Asset              types.Asset  `json:"asset"`
	StartedAt          time.Time    `json:"started_at"`
	SandboxImageDigest string       `json:"sandbox_image_digest"`
	Corpus             types.Corpus `json:"corpus"`
	SignerPublicKey    string       `json:"signer_public_key"`
}

func writeManifest(outDir, scanID string, asset types.Asset, started time.Time, info *sandbox.Info, corpus types.Corpus) error {
	dir := filepath.Join(outDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_, pubHex := signingKey()
	return writeJSON(filepath.Join(dir, "scan_manifest.json"), scanManifest{
		ScanID:             scanID,
		Asset:              asset,
		StartedAt:          started,
		SandboxImageDigest: info.ImageDigest,
		Corpus:             corpus,
		SignerPublicKey:    pubHex,
	})
}

// signingKey loads (or creates) the persistent signing key and returns
// its signer id + public-key hex. Memoized for a single process run.
func signingKey() (signer string, pubHex string) {
	keyOnce.Do(func() {
		priv, sid, err := attest.LoadOrCreate(attest.DefaultKeyPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "[attest] %v\n", err)
			return
		}
		keyPriv = priv
		keySigner = sid
		keyPubHex = attest.PublicKeyHex(priv)
	})
	return keySigner, keyPubHex
}

func signAndWrite(scan *types.Scan, outDir, scanID string) error {
	signer, _ := signingKey()
	if keyPriv == nil {
		return fmt.Errorf("signing key unavailable")
	}
	att, err := dashboard.Sign(*scan, signer, keyPriv, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign attestation: %w", err)
	}
	scan.Attestation = att

	dir := filepath.Join(outDir, scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}
	return writeJSON(filepath.Join(dir, "vulnerabilities.json"), scan)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path) //nolint:gosec // operator-provided path
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newScanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "scan-" + hex.EncodeToString(b)
}

// cloudCredentialEnv collects the provider credential env vars from the
// host environment to forward into the sandbox for a cloud_account
// scan. Only credential-shaped prefixes are forwarded — never the whole
// host environment.
func cloudCredentialEnv() []string {
	prefixes := []string{"AWS_", "GOOGLE_", "GCP_", "AZURE_", "CLOUDSDK_"}
	var out []string
	for _, e := range os.Environ() {
		for _, p := range prefixes {
			if strings.HasPrefix(e, p) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

func shortID(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12]
}

// keep the tool import live (prevent unused-import errors when the
// nuclei/dalfox blank imports above are the only users)
var _ = tool.All
var _ = strings.TrimSpace
