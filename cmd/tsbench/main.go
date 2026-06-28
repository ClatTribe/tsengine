// Command tsbench is the L1 benchmark harness CLI. It runs the real
// tsengine binary against a fixture, scores the output, and prints a
// report that always cites the neutral competitor leaderboard
// (CLAUDE.md §14).
//
//	tsbench run      --fixture <path> [--trials N] [--binary ./bin/tsengine] [--image ref]
//	tsbench ablation --fixture <path> [--trials N]   # L1.5 on vs off
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/cloudbench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudquery"
	"github.com/ClatTribe/tsengine/pkg/types"
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
	case "run":
		if err := runCmd(args[1:], false); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench run: %v\n", err)
			os.Exit(1)
		}
	case "ablation":
		if err := runCmd(args[1:], true); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench ablation: %v\n", err)
			os.Exit(1)
		}
	case "wavsep":
		if err := wavsepCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench wavsep: %v\n", err)
			os.Exit(1)
		}
	case "sast":
		if err := sastCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench sast: %v\n", err)
			os.Exit(1)
		}
	case "cloud":
		if err := cloudCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench cloud: %v\n", err)
			os.Exit(1)
		}
	case "parity":
		if err := parityCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench parity: %v\n", err)
			os.Exit(1)
		}
	case "agent":
		if err := agentCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench agent: %v\n", err)
			os.Exit(1)
		}
	case "xbow":
		if err := xbowCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench xbow: %v\n", err)
			os.Exit(1)
		}
	case "scoreboard":
		if err := scoreboardCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench scoreboard: %v\n", err)
			os.Exit(1)
		}
	case "cloud-engine":
		if err := cloudEngineCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench cloud-engine: %v\n", err)
			os.Exit(1)
		}
	case "cloud-baseline":
		if err := cloudBaselineCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench cloud-baseline: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "tsbench: unknown subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `tsbench — tsengine L1 benchmark harness

Usage:
  tsbench run      --fixture <path> [--trials N] [--binary <path>] [--image <ref>]
  tsbench ablation --fixture <path> [--trials N]
  tsbench wavsep   --target <url> --ground-truth <expected-cases.csv> [--image <ref>]
  tsbench sast     --target <src-dir> --ground-truth <expectedresults.csv> [--image <ref>]
  tsbench cloud    --target <provider> --ground-truth <expected-controls.csv> [--image <ref>]
  tsbench parity   --asset <type> --target <t> --tool <name> [--image <ref>]
  tsbench cloud-engine [--scenarios N] [--real R] [--decoy D] [--seed S]
  tsbench agent    --objectives <fixture.json> --scan <scan.json>
  tsbench xbow     --suite <validation-benchmarks-dir> [--dry-run] [--only ID,…] [--level N] [--out <prefix>]
  tsbench scoreboard [--results <json>] [--out <file>]

Fixtures live under fixtures/. Stub fixtures (runnable:false) need their
corpus deployed out-of-band (WAVSEP webapp, OWASP BenchmarkJava tree).

sast scans a source tree (e.g. the OWASP BenchmarkJava source, extracted from
the strix-bench/owasp-benchmark image) with the repository asset and scores
per-CWE-category Youden vs the SAST leaderboard (Veracode/Checkmarx/Fortify).

cloud scans a cloud account (--target aws|gcp|azure) with the cloud_account
asset (prowler + scoutsuite) and scores per-CIS-section recall against a mock
account seeded with a known-failing posture. Scoped, short-lived credentials
are read from the environment (AWS_*/GOOGLE_*/AZURE_*) and forwarded into the
sandbox — never written to disk. No neutral CSPM leaderboard (Prowler/Scout
Suite/Wiz/Orca self-publish), so the cite is the CIS-recall reference.

xbow runs the XBOW validation-benchmarks suite (github.com/xbow-engineering/
validation-benchmarks): 104 Dockerized web challenges graded on FLAG CAPTURE
(a random flag injected at build time, retrieved only by real exploitation —
deterministic + ungameable). It's XBOW's own public suite, so the solve-rate is
directly comparable to theirs (rung-2 same-suite parity; see docs/xbow-benchmark.md).
--dry-run loads the suite and prints the plan with no Docker/scan; the real run
needs the sandbox image + an LLM for the deep agent.

parity is the differential-recall gate for the asset types with NO public
leaderboard: it runs <tool> standalone (via replay) and through a full scan
against the same target, then asserts the orchestrated run drops nothing the
standalone tool found (recall == 1.0). This proves the L1 best-in-class claim
(CLAUDE.md §2.4 — per-tool recall = the standalone OSS tool) without needing a
public corpus. Cleanest for single-stage assets (repository/container/cloud).
`)
}

// wavsepCmd runs the WAVSEP DAST benchmark: scan the deployed WAVSEP root
// (katana crawls the test-case URLs, the fan-out scans them), then score
// per-category Youden against the ground-truth CSV. Needs the WAVSEP
// webapp reachable + the sandbox image built with katana.
func wavsepCmd(argv []string) error {
	fs := flag.NewFlagSet("wavsep", flag.ContinueOnError)
	target := fs.String("target", "", "deployed WAVSEP root URL (e.g. http://host.docker.internal:8098/wavsep/)")
	groundTruth := fs.String("ground-truth", "", "path to expected-cases.csv (WAVSEP ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (WAVSEP is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *target == "" || *groundTruth == "" {
		return fmt.Errorf("--target and --ground-truth are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunWavsep(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderWavsep(rep))
	return nil
}

// sastCmd runs the OWASP Benchmark v1.2 SAST benchmark: scan a source tree
// (the BenchmarkJava tree — extract it from the strix-bench/owasp-benchmark
// image or clone it) with the repository asset, then score per-CWE-category
// Youden against expectedresults*.csv vs the SAST leaderboard.
func sastCmd(argv []string) error {
	fs := flag.NewFlagSet("sast", flag.ContinueOnError)
	target := fs.String("target", "", "path to the SAST benchmark source tree (e.g. BenchmarkJava)")
	groundTruth := fs.String("ground-truth", "", "path to expectedresults*.csv (OWASP Benchmark ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (the tree is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *target == "" || *groundTruth == "" {
		return fmt.Errorf("--target and --ground-truth are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunSast(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderSast(rep))
	return nil
}

// cloudCmd runs the CIS AWS Foundations CSPM benchmark: scan a cloud account
// (--target aws|gcp|azure) with the cloud_account asset (prowler + scoutsuite),
// then score per-CIS-section recall against a mock account seeded with a
// known-failing posture. Scoped, short-lived credentials are read from the
// environment by the scan CLI and forwarded into the sandbox — never on disk.
// cloudBaselineCmd is the OFFLINE CIS scoreboard (ADR 0009 Phase 3): score our cloud lane's
// CIS-control recall over a fixture account against ground truth, without any sandbox or AWS.
// It runs the deterministic engine (cloudengine.Assess) over the inventory + provided prowler
// findings and reports prowler-only vs tsengine (engine+DSPM/CWPP) recall — the laptop/CI proof
// number that complements the sandbox-gated `tsbench cloud`.
func cloudBaselineCmd(argv []string) error {
	fs := flag.NewFlagSet("cloud-baseline", flag.ContinueOnError)
	dir := fs.String("dir", "bench/cloud_baseline", "fixture dir (inventory.json + prowler.json + ground_truth.json)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	snap, err := cloudgraph.LoadSnapshot(*dir + "/inventory.json")
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}
	var prowler []types.Finding
	if b, rerr := os.ReadFile(*dir + "/prowler.json"); rerr == nil {
		if jerr := json.Unmarshal(b, &prowler); jerr != nil {
			return fmt.Errorf("parse prowler.json: %w", jerr)
		}
	}
	gtBytes, err := os.ReadFile(*dir + "/ground_truth.json")
	if err != nil {
		return fmt.Errorf("read ground_truth.json: %w", err)
	}
	var gt struct {
		Violations []cloudbench.CISExpectation `json:"violations"`
	}
	if jerr := json.Unmarshal(gtBytes, &gt); jerr != nil {
		return fmt.Errorf("parse ground_truth.json: %w", jerr)
	}

	// prowler-only coverage = the resources its findings touch.
	var prowlerRes []string
	for _, f := range prowler {
		prowlerRes = append(prowlerRes, f.Endpoint)
	}
	// tsengine coverage = prowler + everything our engine surfaces (DSPM/CWPP exposures,
	// attack paths) — the affected resources of every assessment finding.
	a := cloudengine.Assess(snap, prowler, cloudengine.SnapshotOracle{}, cloudengine.Options{})
	engineRes := append([]string{}, prowlerRes...)
	for _, p := range a.Paths {
		engineRes = append(engineRes, p.Affected...)
	}

	prowlerScore := cloudbench.ScoreCIS(prowlerRes, gt.Violations)
	engineScore := cloudbench.ScoreCIS(engineRes, gt.Violations)
	fmt.Print(cloudbench.RenderCIS(prowlerScore, engineScore))
	return nil
}

func cloudCmd(argv []string) error {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	target := fs.String("target", "aws", "cloud provider: aws | gcp | azure")
	groundTruth := fs.String("ground-truth", "", "path to expected-controls.csv (CIS ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (a full account sweep is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *groundTruth == "" {
		return fmt.Errorf("--ground-truth is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunCloud(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderCloud(rep))
	return nil
}

// parityCmd runs the differential-recall gate: run a tool standalone (replay)
// and through a full scan against the same target, then assert the orchestrated
// run drops nothing the standalone tool found. Exits non-zero on a parity FAIL
// so CI can gate on it (CLAUDE.md §2.4).
func parityCmd(argv []string) error {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	assetType := fs.String("asset", "", "asset type (repository | container_image | cloud_account | ...)")
	target := fs.String("target", "", "scan target")
	toolName := fs.String("tool", "", "wrapped OSS tool to check parity for (e.g. trivy, prowler, semgrep)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "10m", "per-scan timeout")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *assetType == "" || *target == "" || *toolName == "" {
		return fmt.Errorf("--asset, --target and --tool are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunParity(ctx, *assetType, *target, *toolName,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderParity(rep))
	if !rep.Result.Pass {
		os.Exit(3)
	}
	return nil
}

// agentCmd scores the L2 agent's autonomous performance — detection_rate,
// verified_rate (the XBOW exploitation-verified bar), completion_rate, and FP
// control — against an objectives fixture. It grades a saved scan JSON
// (`tsengine scan -o scan.json`, which runs L1+L2), so the metric is
// reproducible without a live LLM key in CI.
//
//	tsbench agent --objectives fixtures/agent/objectives.example.json --scan scan.json
func agentCmd(argv []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	objectives := fs.String("objectives", "", "path to the agent objectives fixture JSON")
	scanPath := fs.String("scan", "", "path to a saved scan JSON (tsengine scan -o output) to grade")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *objectives == "" || *scanPath == "" {
		return fmt.Errorf("--objectives and --scan are required")
	}
	obj, err := bench.LoadAgentObjectives(*objectives)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*scanPath) //nolint:gosec // operator-provided scan path
	if err != nil {
		return fmt.Errorf("read scan %s: %w", *scanPath, err)
	}
	var scan types.Scan
	if err := json.Unmarshal(data, &scan); err != nil {
		return fmt.Errorf("parse scan %s: %w", *scanPath, err)
	}
	rep := bench.ScoreAgent(obj, &scan)
	fmt.Print(bench.RenderAgent(rep))
	if !rep.Pass {
		return fmt.Errorf("gate failed: %s", rep.Reason)
	}
	return nil
}

// scoreboardCmd renders the unified competitive scorecard (Track 1/A2): every
// benchmark lane's latest measured number against its competitor bar, with an
// at-par verdict. Numbers come from a results JSON ({category_key: fraction});
// missing lanes render as "pending a live run".
//
//	tsbench scoreboard --results bench/scoreboard.results.json --out SCOREBOARD.md
func scoreboardCmd(argv []string) error {
	fs := flag.NewFlagSet("scoreboard", flag.ContinueOnError)
	resultsPath := fs.String("results", "", "optional JSON: {category_key: measured_fraction}")
	out := fs.String("out", "", "optional output file (default stdout)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	results := map[string]float64{}
	if *resultsPath != "" {
		data, err := os.ReadFile(*resultsPath) //nolint:gosec // operator-provided results path
		if err != nil {
			return fmt.Errorf("read results %s: %w", *resultsPath, err)
		}
		if err := json.Unmarshal(data, &results); err != nil {
			return fmt.Errorf("parse results %s: %w", *resultsPath, err)
		}
	}
	md := bench.Scoreboard(results)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil { //nolint:gosec // human-readable report
			return fmt.Errorf("write %s: %w", *out, err)
		}
		fmt.Printf("wrote %s\n", *out)
		return nil
	}
	fmt.Print(md)
	return nil
}

// cloudEngineCmd runs the AI Cloud Security Engineer benchmark (Tier 2,
// synthetic): generate N scenarios with planted attack paths + config-bad-but-
// inert decoys, deterministically verify each, run the engine, and score
// attack-path recall + FP-reduction. No cloud/infra — the engineer reasons over
// the synthetic snapshot (docs/design/ai-cloud-engineer.md §6).
func cloudEngineCmd(argv []string) error {
	fs := flag.NewFlagSet("cloud-engine", flag.ContinueOnError)
	scenarios := fs.Int("scenarios", 50, "number of synthetic scenarios")
	real := fs.Int("real", 3, "planted real network→data attack paths per scenario")
	decoy := fs.Int("decoy", 2, "config-bad-but-inert decoys per scenario")
	privesc := fs.Bool("privesc", true, "include an IAM privesc-to-admin chain per scenario")
	seed := fs.Int64("seed", 1, "base seed (scenario i uses seed+i)")
	maxHyp := fs.Int("max-hypotheses", 0, "engine worklist budget (0 = production default 20); raise to stress-test many real paths")
	emit := fs.String("emit", "", "write ONE synthetic emulated cloud account to <path> (inventory JSON + <path>.prowler.json) and exit")
	holdout := fs.Int("holdout", 0, "run the HELD-OUT generalization benchmark over N accounts (anti-overfit: independent ground truth) and exit")
	holdoutK := fs.Int("holdout-k", 2, "per held-out account: K fragments of each posture class")
	llmEmulate := fs.Bool("llm-emulate", false, "generate an INDEPENDENT emulated account with an external LLM, run the engine on it, score vs the model's answer key, and exit")
	emOut := fs.String("emulate-out", "", "with --llm-emulate: write the generated inventory + prowler + answer key under this path prefix")
	cqRun := fs.Bool("cloudquery", false, "emulate a prowler-grounded CloudQuery account, run the engineer on it (effective-perms ingest), score vs the cloudiam answer key, and exit")
	cqDir := fs.String("cloudquery-dir", "", "load a CloudQuery dataset from this dir instead of generating (one JSON per table)")
	cqEmit := fs.String("cloudquery-emit", "", "write the emulated CloudQuery dataset (one JSON per table) to this dir and exit")
	cqAdvanced := fs.Bool("cloudquery-advanced", false, "use the advanced scenario (resource-policy-only grant + SCP-blocked privesc) to show effective-permission reasoning")
	cqLarge := fs.Bool("cloudquery-large", false, "generate a large, realistic CloudQuery account (hundreds of resources + noise) with planted paths and an independent answer key")
	cqSize := fs.Int("size", 300, "with --cloudquery-large: approximate account size (number of benign principals; other counts scale from it)")
	cqEmitInv := fs.String("cloudquery-emit-inventory", "", "write the RESOLVED inventory + prowler findings (the `tsengine cloud-assess` input) to <prefix>.json / <prefix>.prowler.json and exit")
	cqAgent := fs.Bool("agent", false, "also run the LLM agent (cloudagent) over the same account and score it head-to-head vs the deterministic engine (needs LLM_API_KEY)")
	cloudgoat := fs.Bool("cloudgoat", false, "Tier-1 calibration: run the engineer over transcribed CloudGoat scenarios and score vs their PUBLISHED pentest solutions (ground truth ≠ cloudiam), and exit")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	// Tier-1 fidelity calibration vs CloudGoat (Rhino Security Labs): the ground
	// truth is the scenarios' documented real-lab compromise, so cloudiam is under
	// test rather than the referee.
	if *cloudgoat {
		return runCloudGoat(*maxHyp)
	}

	// Prowler-grounded CloudQuery path: prowler's catalog defines "bad" over the
	// CloudQuery config; cloudiam (trust policies + permission boundaries) defines
	// exploitability truth; the engineer ingests CloudQuery (resolving effective
	// perms) and is scored against that independent key.
	if *cqRun || *cqEmit != "" || *cqEmitInv != "" {
		return runCloudQuery(cqOpts{loadDir: *cqDir, emitDir: *cqEmit, emitInv: *cqEmitInv, maxHyp: *maxHyp,
			advanced: *cqAdvanced, large: *cqLarge, size: *cqSize, seed: *seed, agent: *cqAgent})
	}

	// Independent-generator check: an external model authors the account AND its
	// answer key; the engine reasons over the CloudQuery-style inventory and is
	// scored against the key it never saw (neither side can collude).
	if *llmEmulate {
		return runLLMEmulate(*seed, *real, *decoy, *maxHyp, *emOut)
	}

	// Emulated-account export: serialize one scenario to an inventory JSON the
	// real pipeline (tsengine cloud-assess / scan) can consume — no real AWS.
	if *emit != "" {
		return cloudengine.EmitScenario(*emit, *seed, *real, *decoy, *privesc)
	}

	// Held-out generalization benchmark: prowler-check-derived postures with
	// INDEPENDENT ground truth (cloudiam eval incl. boundaries + trust policies),
	// measuring the overfit gap the in-distribution bench cannot see.
	if *holdout > 0 {
		agg, n, err := cloudengine.RunHoldout(*seed, *holdout, *holdoutK, *maxHyp)
		if err != nil {
			return err
		}
		fmt.Print(cloudengine.RenderHoldout(agg, n))
		if !agg.Pass {
			os.Exit(3)
		}
		return nil
	}

	agg, n, err := cloudengine.RunSynthetic(*seed, *scenarios, *real, *decoy, *privesc, *maxHyp)
	if err != nil {
		return err
	}
	fmt.Print(cloudengine.RenderEngineScore(agg, n))
	if !agg.Pass {
		os.Exit(3)
	}
	return nil
}

// runLLMEmulate has an external model author an emulated account + answer key,
// runs the engine over the CloudQuery-style inventory, and scores the engine
// against the key it never saw. The key is read from the environment by the
// Gemini client (x-goog-api-key header) — never printed.
func runLLMEmulate(seed int64, nReal, nDecoy, maxHyp int, outPrefix string) error {
	llm, ok := cloudengine.GeminiFromEnv()
	if !ok {
		return fmt.Errorf("--llm-emulate requires LLM_API_KEY (the external generator)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	acc, err := cloudengine.GenerateEmulated(ctx, llm, nReal, nDecoy)
	if err != nil {
		return err
	}
	snap, err := acc.Snapshot() // serialize → ParseInventory → Ingest (the cloud-assess path)
	if err != nil {
		return err
	}
	a := cloudengine.Assess(snap, acc.Prowler, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: maxHyp})
	s := cloudengine.ScoreEmulated(acc, a)

	fmt.Print(cloudengine.RenderEmulated(acc, s))
	fmt.Println()
	fmt.Print(cloudengine.RenderAssessment(a))

	if outPrefix != "" {
		if werr := writeEmulated(outPrefix, acc); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[llm-emulate] wrote %s.json (+ .prowler.json, .answerkey.json) — re-run with: tsengine cloud-assess --snapshot %s.json --prowler %s.prowler.json\n",
			outPrefix, outPrefix, outPrefix)
	}
	if !s.Pass {
		os.Exit(3)
	}
	return nil
}

// runCloudQuery emulates (or loads) a prowler-grounded CloudQuery account, runs
// the AI Cloud Security Engineer over it via the effective-permission resolving
// ingest, and scores the result against the independent cloudiam answer key.
type cqOpts struct {
	loadDir, emitDir, emitInv string
	maxHyp, size              int
	advanced, large, agent    bool
	seed                      int64
}

func runCloudQuery(o cqOpts) error {
	// Resolve the dataset: load from a dir (with its answer key), else generate.
	var ds *cloudquery.Dataset
	var err error
	switch {
	case o.loadDir != "":
		ds, err = cloudquery.LoadDataset(o.loadDir)
	case o.large:
		ds, err = cloudquery.GenerateLarge(cloudquery.SizedLargeOpts(o.seed, o.size))
	case o.advanced:
		ds, err = cloudquery.GenerateAdvanced()
	default:
		ds, err = cloudquery.Generate()
	}
	if err != nil {
		return fmt.Errorf("cloudquery: dataset: %w", err)
	}

	// --cloudquery-emit: persist tables + answer key and exit.
	if o.emitDir != "" {
		if werr := ds.SaveAll(o.emitDir); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[cloudquery] wrote dataset → %s/ (CloudQuery tables + answer_key.json)\n  %s\n", o.emitDir, ds.Stats())
		return nil
	}

	// --cloudquery-emit-inventory: write the RESOLVED inventory + prowler findings
	// — the operator-facing input that `tsengine cloud-assess` (the full AI engineer
	// + LLM) consumes. This bridges a CloudQuery dataset into the real pipeline.
	if o.emitInv != "" {
		base := strings.TrimSuffix(o.emitInv, ".json")
		invJSON, merr := json.MarshalIndent(cloudquery.ToInventory(ds.Tables), "", "  ")
		if merr != nil {
			return merr
		}
		if werr := os.WriteFile(base+".json", invJSON, 0o600); werr != nil {
			return werr
		}
		prowJSON, perr := json.MarshalIndent(cloudquery.EvalProwler(ds.Tables), "", "  ")
		if perr != nil {
			return perr
		}
		if werr := os.WriteFile(base+".prowler.json", prowJSON, 0o600); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "[cloudquery] wrote %s.json (+ .prowler.json) — run: tsengine cloud-assess --snapshot %s.json --prowler %s.prowler.json --llm on --max-hypotheses %d\n  %s\n",
			base, base, base, max(150, len(ds.AnswerKey.RealTargets)*8), ds.Stats())
		return nil
	}

	// A large account needs a worklist budget big enough to validate every planted
	// path; default it generously when the operator did not set one.
	maxHyp := o.maxHyp
	if o.large && maxHyp == 0 {
		maxHyp = max(150, len(ds.AnswerKey.RealTargets)*8)
	}

	findings := cloudquery.EvalProwler(ds.Tables) // prowler "tools say"
	inv := cloudquery.ToInventory(ds.Tables)      // effective-perms resolution (the eyes)
	snap := cloudgraph.Ingest(inv)                // the engineer's pinned graph
	a := cloudengine.Assess(snap, findings, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: maxHyp})
	s := cloudquery.ScoreAssessment(ds, a)

	fmt.Print(cloudquery.Render(ds, findings, a, s))
	if !o.large { // the per-path detail + remediations are noise on a large account
		fmt.Println()
		fmt.Print(cloudengine.RenderAssessment(a))
		fmt.Println()
		fmt.Print(cloudengine.RenderRemediations(cloudengine.GenerateRemediations(a)))
	}

	// --agent: run the LLM agent over the SAME account and score it head-to-head
	// against the deterministic engine, both vs the independent answer key.
	if o.agent {
		llm, ok := cloudengine.GeminiFromEnv()
		if !ok {
			return fmt.Errorf("--agent needs LLM_API_KEY (the agent's brain)")
		}
		cc := &cloudagent.Context{Snap: snap, Prowler: findings}
		rep, aerr := cloudagent.Investigate(context.Background(), llm, cc, cloudagent.Options{MaxIters: 4*len(ds.AnswerKey.RealTargets) + 12, MaxHyp: maxHyp})
		if aerr != nil {
			return aerr
		}
		as := rep.Score(ds.AnswerKey.RealTargets)
		fmt.Printf("\n=== head-to-head on the same account (vs the independent answer key) ===\n")
		fmt.Printf("deterministic engine: recall %.2f%% (%d/%d), FP-reduction %.2f%%, false paths %d\n",
			s.PathRecall*100, s.RealFound, s.RealTotal, s.FPReduction*100, len(s.Extra))
		fmt.Printf("LLM agent           : %s", cloudagent.RenderScore(as))
		fmt.Print(cloudagent.Render(rep))
		if !as.Pass {
			os.Exit(3)
		}
		return nil
	}

	if !s.Pass {
		os.Exit(3)
	}
	return nil
}

// runCloudGoat runs the Tier-1 calibration: the engineer over transcribed
// CloudGoat scenarios, scored against their published pentest solutions.
func runCloudGoat(maxHyp int) error {
	var results []cloudquery.Tier1Result
	allPass := true
	for _, sc := range cloudquery.Tier1Scenarios() {
		r, _ := cloudquery.RunTier1(sc, maxHyp)
		results = append(results, r)
		if !r.Pass {
			allPass = false
		}
	}
	fmt.Print(cloudquery.RenderTier1(results))
	if !allPass {
		os.Exit(3)
	}
	return nil
}

func writeEmulated(prefix string, acc *cloudengine.EmulatedAccount) error {
	base := strings.TrimSuffix(prefix, ".json")
	inv, err := json.MarshalIndent(acc.Inventory, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(base+".json", inv, 0o600); err != nil {
		return err
	}
	prow, err := json.MarshalIndent(acc.Prowler, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(base+".prowler.json", prow, 0o600); err != nil {
		return err
	}
	key, err := json.MarshalIndent(acc.Key, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(base+".answerkey.json", key, 0o600)
}

func runCmd(argv []string, ablation bool) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fixturePath := fs.String("fixture", "", "path to fixture dir or fixture.json")
	trials := fs.Int("trials", 1, "trial count (median + p10/p90 over N)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	// 600s, not 300s: a COLD container_image bench (trivy DB download + the image pull happening
	// INSIDE the sandbox on the first run) doesn't finish in 300s, which truncated the scan and
	// produced a false FAIL (recall 0.000 with only the fast tools' findings). 600s covers a cold
	// run; warm runs still finish early (it's a cap, not a fixed wait).
	timeout := fs.String("timeout", "600s", "per-scan timeout")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *fixturePath == "" {
		return fmt.Errorf("--fixture is required")
	}

	f, err := bench.Load(*fixturePath)
	if err != nil {
		return err
	}

	if !f.Runnable {
		// Stub fixture: print its competitor numbers + why it can't run.
		fmt.Print(bench.RenderStub(f))
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 30*time.Minute)
	defer cancelT()

	opts := bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout, Trials: *trials}

	if ablation {
		a, err := bench.RunAblation(ctx, f, opts)
		if err != nil {
			return err
		}
		fmt.Print(bench.Render(f, a.Enabled))
		fmt.Print(bench.RenderAblation(f, a))
		if !a.Enabled.AllPass {
			os.Exit(3)
		}
		return nil
	}

	res, err := bench.Run(ctx, f, opts)
	if err != nil {
		return err
	}
	fmt.Print(bench.Render(f, res))
	if !res.AllPass {
		os.Exit(3)
	}
	return nil
}
