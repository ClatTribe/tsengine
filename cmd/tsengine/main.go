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
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/corpus/threatintel"
	"github.com/ClatTribe/tsengine/internal/dashboard"
	"github.com/ClatTribe/tsengine/internal/orchestrator"
	"github.com/ClatTribe/tsengine/internal/replay"
	"github.com/ClatTribe/tsengine/internal/sandbox"
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
