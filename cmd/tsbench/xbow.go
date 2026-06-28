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
	timeout := fs.String("timeout", "12m", "per-benchmark scan timeout")
	only := fs.String("only", "", "comma-separated benchmark IDs to run (default: all)")
	level := fs.Int("level", 0, "only run benchmarks of this difficulty level (1/2/3; 0 = all)")
	targetPort := fs.String("target-port", "", "host port the benchmark publishes (skip docker-compose port autodetect)")
	out := fs.String("out", "", "write <out>.json (results) + <out>.md (scoreboard); default stdout only")
	dryRun := fs.Bool("dry-run", false, "load the suite and print the plan WITHOUT Docker/scan (suite-wiring check)")
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

	if *dryRun {
		fmt.Printf("=== XBOW suite plan (%d benchmarks) ===\n", len(benches))
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

	var results []bench.XBOWResult
	for i, b := range benches {
		fmt.Fprintf(os.Stderr, "[xbow %d/%d] %s (level %d) …\n", i+1, len(benches), b.ID, b.Config.Level)
		r := runOneXBOW(ctx, b, *binary, *timeout, *targetPort)
		status := "MISS"
		if r.Solved {
			status = "SOLVED"
		}
		fmt.Fprintf(os.Stderr, "  → %s (%.0fs) %s\n", status, r.Duration, r.Note)
		results = append(results, r)
	}

	sb := bench.AggregateXBOW(results)
	report := bench.RenderXBOWScoreboard(sb)
	fmt.Print(report)

	if *out != "" {
		if jerr := writeXBOWResults(*out, results, sb); jerr != nil {
			return jerr
		}
		fmt.Fprintf(os.Stderr, "[xbow] wrote %s.json + %s.md\n", *out, *out)
	}
	return nil
}

// runOneXBOW builds, runs, scans, grades, and tears down a single benchmark. It ALWAYS tears the
// compose stack down (deferred) so a failed run never leaks containers. A build/up/target/scan
// failure is recorded as an unsolved result with the error note — the run continues to the next
// benchmark rather than aborting the whole suite.
func runOneXBOW(ctx context.Context, b bench.XBOWBenchmark, binary, timeout, targetPort string) bench.XBOWResult {
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
		_, _ = compose_(ctx, compose, "down", "-v")
		return finish("compose up failed: " + tail(out))
	}
	defer func() { _, _ = compose_(ctx, compose, "down", "-v") }()

	target := ""
	if targetPort != "" {
		target = "http://localhost:" + targetPort
	} else if p := composePort(ctx, compose); p != "" {
		target = "http://localhost:" + p
	}
	if target == "" {
		return finish("could not determine target URL (set --target-port)")
	}

	// scan the target with the deep agent. Env (LLM_*, TSENGINE_ACTIVE_EXPLOIT, sandbox image) is
	// inherited from this process, so the operator controls the agent's brain + exploitation gate.
	tmp, err := os.MkdirTemp("", "xbow-scan-")
	if err != nil {
		return finish("mktemp: " + err.Error())
	}
	defer os.RemoveAll(tmp)
	sctx, scancel := context.WithTimeout(ctx, parseDur(timeout))
	defer scancel()
	cmd := exec.CommandContext(sctx, binary, "scan", "--asset", "web_application",
		"--target", target, "--out", tmp, "--timeout", timeout)
	cmd.Env = os.Environ()
	if scanOut, serr := cmd.CombinedOutput(); serr != nil {
		// a non-zero scan exit still may have written a partial report — try to grade it anyway.
		if scan := loadScanReport(tmp); scan != nil && bench.FlagCapturedInScan(flagStr, scan) {
			res.Solved = true
			return finish("flag captured (scan exited " + serr.Error() + ")")
		}
		return finish("scan failed: " + tail(string(scanOut)))
	}

	scan := loadScanReport(tmp)
	if scan == nil {
		return finish("no vulnerabilities.json produced")
	}
	if bench.FlagCapturedInScan(flagStr, scan) {
		res.Solved = true
		return finish("flag captured")
	}
	return finish("flag not captured")
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
