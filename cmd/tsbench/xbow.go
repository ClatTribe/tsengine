package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// xbowCmd runs the XBOW validation-benchmarks suite (rung-2 same-suite comparison): for each
// benchmark it injects a random flag at build time, spins up the vulnerable app, runs the tsengine
// deep pentest agent against it, and grades on FLAG CAPTURE (deterministic + ungameable). The number
// is directly comparable to XBOW's published solve-rate on the same 104 challenges.
//
//	# clone the suite, build the sandbox image, point an LLM at the agent, then:
//	TSENGINE_SANDBOX_IMAGE=tsengine/sandbox:0.1.0 TSENGINE_ACTIVE_EXPLOIT=1 \
//	LLM_BASE_URL=… LLM_MODEL=… LLM_API_KEY=… \
//	  tsbench xbow --suite ./validation-benchmarks --out xbow-scoreboard
//
// The build/up/scan/down loop is Docker + sandbox-image + LLM gated; --dry-run validates the suite
// loads + prints the plan with none of that. The pure parse/grade/aggregate logic is unit-tested
// (internal/bench/xbow_test.go), so the metric is correct before the first heavy run.
func xbowCmd(argv []string) error {
	fs := flag.NewFlagSet("xbow", flag.ContinueOnError)
	suite := fs.String("suite", "", "path to a cloned github.com/xbow-engineering/validation-benchmarks tree")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path (runs the deep agent)")
	mode := fs.String("mode", "investigate", "investigate = the offensive LLM agent that PURSUES the flag (web-investigate); scan = deterministic L1 detection only (finds vulns, cannot capture a flag by design)")
	timeout := fs.String("timeout", "12m", "per-benchmark scan timeout")
	only := fs.String("only", "", "comma-separated benchmark IDs to run (default: all)")
	level := fs.Int("level", 0, "only run benchmarks of this difficulty level (1/2/3; 0 = all)")
	targetPort := fs.String("target-port", "", "host port the benchmark publishes (skip docker-compose port autodetect)")
	out := fs.String("out", "", "write <out>.json (results) + <out>.md (scoreboard); default stdout only")
	dryRun := fs.Bool("dry-run", false, "load the suite and print the plan WITHOUT Docker/scan (suite-wiring check)")
	resume := fs.Bool("resume", false, "skip benchmarks already in <out>.json (resume a long/interrupted run)")
	prune := fs.Bool("prune-images", true, "remove each benchmark's locally-built image after teardown (bounds disk over a full-suite run)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *suite == "" {
		return fmt.Errorf("--suite is required (clone github.com/xbow-engineering/validation-benchmarks)")
	}

	benches, err := bench.LoadXBOWSuite(*suite)
	if err != nil {
		return err
	}
	benches = filterXBOW(benches, *only, *level)
	if len(benches) == 0 {
		return fmt.Errorf("no benchmarks matched --only/--level")
	}

	switch *mode {
	case "investigate", "scan":
	default:
		return fmt.Errorf("--mode must be investigate or scan, got %q", *mode)
	}

	if *dryRun {
		fmt.Printf("=== XBOW suite plan (%d benchmarks, mode=%s) ===\n", len(benches), *mode)
		for _, b := range benches {
			compose := b.ComposeFile()
			if compose == "" {
				compose = "(no docker-compose found!)"
			}
			fmt.Printf("  %-16s level=%d win=%-5s tags=%v\n      %s\n",
				b.ID, b.Config.Level, b.Config.WinCondition, b.Config.Tags, compose)
		}
		fmt.Printf("\nDry run — no Docker, no scan. Re-run without --dry-run (with the sandbox image + an LLM) to measure flag-capture.\n")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Resume: carry forward results already checkpointed in <out>.json and skip those benchmarks. A
	// 104-benchmark run is 12–28h on a laptop, so it MUST survive a crash/throttle/sleep/Ctrl-C.
	var results []bench.XBOWResult
	done := map[string]bool{}
	if *resume && *out != "" {
		for _, r := range loadXBOWCheckpoint(*out) {
			results = append(results, r)
			done[r.ID] = true
		}
		if len(done) > 0 {
			fmt.Fprintf(os.Stderr, "[xbow] resuming: %d benchmarks already done, skipping them\n", len(done))
		}
	}

	for i, b := range benches {
		if done[b.ID] {
			continue
		}
		fmt.Fprintf(os.Stderr, "[xbow %d/%d] %s (level %d) …\n", i+1, len(benches), b.ID, b.Config.Level)
		r := runOneXBOW(ctx, b, *binary, *mode, *timeout, *targetPort, *prune)
		status := "MISS"
		if r.Solved {
			status = "SOLVED"
		}
		fmt.Fprintf(os.Stderr, "  → %s (%.0fs) %s\n", status, r.Duration, r.Note)
		results = append(results, r)
		// Checkpoint after EVERY benchmark so an interrupted run loses nothing (and is resumable).
		if *out != "" {
			if jerr := writeXBOWResults(*out, results, bench.AggregateXBOW(results)); jerr != nil {
				fmt.Fprintf(os.Stderr, "[xbow] checkpoint write failed: %v\n", jerr)
			}
		}
	}

	sb := bench.AggregateXBOW(results)
	fmt.Print(bench.RenderXBOWScoreboard(sb))
	if *out != "" {
		_ = writeXBOWResults(*out, results, sb)
		fmt.Fprintf(os.Stderr, "[xbow] wrote %s.json + %s.md\n", *out, *out)
	}
	return nil
}

// loadXBOWCheckpoint reads the results array from a prior <out>.json (empty on any error — a missing
// or unreadable checkpoint just means "start fresh").
func loadXBOWCheckpoint(prefix string) []bench.XBOWResult {
	data, err := os.ReadFile(prefix + ".json") //nolint:gosec // operator-provided path
	if err != nil {
		return nil
	}
	var payload struct {
		Results []bench.XBOWResult `json:"results"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return nil
	}
	return payload.Results
}

// runOneXBOW builds, runs, scans, grades, and tears down a single benchmark. It ALWAYS tears the
// compose stack down (deferred) so a failed run never leaks containers. A build/up/target/scan
// failure is recorded as an unsolved result with the error note — the run continues to the next
// benchmark rather than aborting the whole suite.
func runOneXBOW(ctx context.Context, b bench.XBOWBenchmark, binary, mode, timeout, targetPort string, pruneImages bool) bench.XBOWResult {
	start := time.Now()
	res := bench.XBOWResult{ID: b.ID, Name: b.Config.Name, Level: b.Config.Level, Tags: b.Config.Tags}
	finish := func(note string) bench.XBOWResult {
		res.Duration = time.Since(start).Seconds()
		res.Note = note
		return res
	}

	compose := b.ComposeFile()
	if compose == "" {
		return finish("no docker-compose file in benchmark dir")
	}
	flagStr, err := bench.GenerateFlag()
	if err != nil {
		return finish("flag gen: " + err.Error())
	}

	// build with the random flag injected, then bring the stack up. The suite's compose files consume
	// an uppercase FLAG build-arg; their own Makefile passes BOTH FLAG= and flag=, so we mirror that.
	if out, berr := compose_(ctx, compose, "build", "--build-arg", "FLAG="+flagStr, "--build-arg", "flag="+flagStr); berr != nil {
		return finish("compose build failed: " + tail(out))
	}
	if out, uerr := compose_(ctx, compose, "up", "-d", "--wait"); uerr != nil {
		_, _ = composeDown(ctx, compose, pruneImages)
		return finish("compose up failed: " + tail(out))
	}
	// Always tear down. On a full-suite run, --prune-images also removes the locally-built image so 104
	// builds don't exhaust the disk (the cost: a rebuild if you resume that benchmark).
	defer func() { _, _ = composeDown(ctx, compose, pruneImages) }()

	target := ""
	if targetPort != "" {
		target = "http://localhost:" + targetPort
	} else if p := composePort(ctx, compose); p != "" {
		target = "http://localhost:" + p
	}
	if target == "" {
		return finish("could not determine target URL (set --target-port)")
	}

	// Env (LLM_*, TSENGINE_ACTIVE_EXPLOIT, sandbox image) is inherited from this process, so the
	// operator controls the agent's brain + exploitation gate.
	tmp, err := os.MkdirTemp("", "xbow-run-")
	if err != nil {
		return finish("mktemp: " + err.Error())
	}
	defer os.RemoveAll(tmp)
	sctx, scancel := context.WithTimeout(ctx, parseDur(timeout))
	defer scancel()

	var solved bool
	var findings int
	var note string
	if mode == "scan" {
		// Deterministic L1 detection: finds + classifies vulns. It CANNOT capture a flag by
		// design (no goal-directed exfil loop) — kept for the findings-count diagnostic + A/B.
		solved, findings, note = gradeScanMode(sctx, binary, timeout, target, tmp, flagStr)
	} else {
		// The OFFENSIVE agent that PURSUES the flag (web-investigate): LLM brain drives crafted
		// requests, reads responses, records grounded findings. This is the flag-capture path.
		solved, findings, note = gradeInvestigateMode(sctx, binary, timeout, target, tmp, flagStr)
	}
	res.Solved, res.Findings = solved, findings
	return finish(note)
}

// gradeScanMode runs the deterministic detector (`tsengine scan`) and grades flag capture over the
// produced vulnerabilities.json. Detection can't pursue a flag, so this is the diagnostic/A-B arm.
func gradeScanMode(ctx context.Context, binary, timeout, target, tmp, flagStr string) (bool, int, string) {
	cmd := exec.CommandContext(ctx, binary, "scan", "--asset", "web_application",
		"--target", target, "--out", tmp, "--timeout", timeout)
	cmd.Env = os.Environ()
	out, serr := cmd.CombinedOutput()
	scan := loadScanReport(tmp) // may exist even on a non-zero exit (partial report)
	findings := 0
	if scan != nil {
		findings = len(scan.FindingsRaw)
		if len(scan.FindingsEnriched) > findings {
			findings = len(scan.FindingsEnriched)
		}
		if bench.FlagCapturedInScan(flagStr, scan) {
			return true, findings, fmt.Sprintf("flag captured (%d findings)", findings)
		}
	}
	if serr != nil {
		return false, findings, "scan failed: " + tail(string(out))
	}
	if scan == nil {
		return false, findings, "no vulnerabilities.json produced"
	}
	return false, findings, fmt.Sprintf("flag not captured (%d findings — reached the app, didn't reach the flag)", findings)
}

// gradeInvestigateMode runs the offensive LLM agent (`tsengine web-investigate`) that PURSUES the
// flag, and grades capture over the UNION of everything it produced: stdout render + the full
// transcript (every turn's response body) + the signed evidence bundle. If the injected random flag
// appears anywhere the agent observed it, that is a real, ungameable capture (§10).
func gradeInvestigateMode(ctx context.Context, binary, timeout, target, tmp, flagStr string) (bool, int, string) {
	transcript := filepath.Join(tmp, "transcript.json")
	evidence := filepath.Join(tmp, "evidence.json")
	cmd := exec.CommandContext(ctx, binary, "web-investigate",
		"--target", target,
		"--transcript", transcript,
		"--export-evidence", evidence,
		"--max-requests", "150",
		"--max-iters", "40")
	cmd.Env = os.Environ()
	out, ierr := cmd.CombinedOutput()

	blob := string(out)
	tData, _ := os.ReadFile(transcript) //nolint:gosec // our own temp dir
	blob += "\n" + string(tData)
	eData, _ := os.ReadFile(evidence) //nolint:gosec // our own temp dir
	blob += "\n" + string(eData)

	findings, turns := investigateCounts(tData)
	if bench.FlagCaptured(flagStr, blob) {
		return true, findings, fmt.Sprintf("flag captured (%d finding(s), %d turn(s), offensive agent)", findings, turns)
	}
	if ierr != nil {
		note := tail(string(out))
		if strings.Contains(note, "needs an LLM") {
			return false, findings, "web-investigate needs an LLM (set LLM_* / LLM_API_KEY) — the flag-pursuit brain"
		}
		if turns > 0 {
			// Killed mid-engagement (usually the per-benchmark timeout on a slow model). The partial
			// transcript WAS flushed + graded above (Options.Progress) — the flag just wasn't in it yet.
			return false, findings, fmt.Sprintf("agent engaged %d turn(s) then stopped (timeout?) — no flag in partial transcript", turns)
		}
		if note == "" {
			note = "killed before any turn completed (timeout before the model's first reply?)"
		}
		return false, findings, "web-investigate failed: " + note
	}
	return false, findings, fmt.Sprintf("flag not captured (%d finding(s), %d turn(s) — agent engaged, didn't reach the flag)", findings, turns)
}

// investigateCounts pulls the recorded-finding count + the turn (request) count from the agent
// transcript (0,0 on any parse error — a missing count is diagnostic, never fatal). Turns > 0 on a
// failed run means the agent DID engage the target before it was stopped (vs. never starting).
func investigateCounts(transcript []byte) (findings, turns int) {
	if len(transcript) == 0 {
		return 0, 0
	}
	var t struct {
		Findings []json.RawMessage `json:"findings"`
		History  []json.RawMessage `json:"history"`
	}
	if json.Unmarshal(transcript, &t) != nil {
		return 0, 0
	}
	return len(t.Findings), len(t.History)
}

// composeDown tears down the stack; with prune it also removes the locally-built image (so a long
// full-suite run can't fill the disk). Best-effort — teardown failures never affect the result.
func composeDown(ctx context.Context, compose string, prune bool) (string, error) {
	if prune {
		return compose_(ctx, compose, "down", "-v", "--rmi", "local")
	}
	return compose_(ctx, compose, "down", "-v")
}

// compose_ runs `docker compose -f <file> <args…>` in the compose file's directory. The path is made
// ABSOLUTE first: a relative -f resolved against a relative cmd.Dir would double the path.
func compose_(ctx context.Context, composeFile string, args ...string) (string, error) {
	abs, err := filepath.Abs(composeFile)
	if err != nil {
		abs = composeFile
	}
	full := append([]string{"compose", "-f", abs}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Dir = filepath.Dir(abs)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// composePort autodetects the first published host TCP port of the compose stack via
// `docker compose ps --format json` (one JSON object per line in modern compose).
func composePort(ctx context.Context, composeFile string) string {
	out, err := compose_(ctx, composeFile, "ps", "--format", "json")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Publishers []struct {
				PublishedPort int `json:"PublishedPort"`
			} `json:"Publishers"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		for _, p := range row.Publishers {
			if p.PublishedPort > 0 {
				return fmt.Sprintf("%d", p.PublishedPort)
			}
		}
	}
	return ""
}

// loadScanReport finds and parses the vulnerabilities.json the scan wrote under outDir (the scan
// nests it in a per-scan subdir).
func loadScanReport(outDir string) *types.Scan {
	var found string
	_ = filepath.WalkDir(outDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "vulnerabilities.json" {
			found = path
		}
		return nil
	})
	if found == "" {
		return nil
	}
	data, err := os.ReadFile(found) //nolint:gosec // path derived from our own temp dir
	if err != nil {
		return nil
	}
	var scan types.Scan
	if json.Unmarshal(data, &scan) != nil {
		return nil
	}
	return &scan
}

func filterXBOW(in []bench.XBOWBenchmark, only string, level int) []bench.XBOWBenchmark {
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	var out []bench.XBOWBenchmark
	for _, b := range in {
		if len(want) > 0 && !want[b.ID] {
			continue
		}
		if level != 0 && b.Config.Level != level {
			continue
		}
		out = append(out, b)
	}
	return out
}

func writeXBOWResults(prefix string, results []bench.XBOWResult, sb bench.XBOWScoreboard) error {
	payload := struct {
		Scoreboard bench.XBOWScoreboard `json:"scoreboard"`
		Results    []bench.XBOWResult   `json:"results"`
	}{sb, results}
	j, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".json", j, 0o644); err != nil { //nolint:gosec // human-readable report
		return err
	}
	return os.WriteFile(prefix+".md", []byte(bench.RenderXBOWScoreboard(sb)), 0o644) //nolint:gosec // human-readable report
}

// tail returns the last ~280 chars of a command's output for a compact error note.
func tail(s string) string {
	s = strings.TrimSpace(s)
	const n = 280
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// parseDur parses a Go duration, defaulting to 12m on any error so a bad --timeout never panics.
func parseDur(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return 12 * time.Minute
}
