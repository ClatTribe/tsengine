package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// defensexbow.go is `tsbench defense-xbow` — the XBOW-DERIVED defense benchmark runner (ADR 0014). For each
// challenge it: builds the vuln app (in an ISOLATED temp COPY of the benchmark dir — never touching the
// shared suite), runs the offensive agent to CAPTURE the flag + record the winning exploit, hands the AI
// Security Engineer the finding + source to PATCH, rebuilds, REPLAYS the recorded exploit + a regression
// check, and grades remediation-capture. Disk-conscious: one temp copy + one image at a time, torn down
// with `--rmi local` after each. Honest: no LLM → skip; can't capture → not_vulnerable (never a fake fix).

func defenseXbowCmd(argv []string) error {
	fs := flag.NewFlagSet("defense-xbow", flag.ContinueOnError)
	suite := fs.String("suite", "../validation-benchmarks", "path to the XBOW validation-benchmarks suite")
	only := fs.String("only", "", "comma-separated benchmark ids to run (e.g. XBEN-001-24)")
	category := fs.String("category", "", "run only benchmarks whose first tag matches this vuln class (e.g. sqli)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary (the offensive agent)")
	timeout := fs.String("timeout", "20m", "per-phase timeout (attack + rebuild)")
	targetPort := fs.String("target-port", "", "override the published web port")
	exploitsDir := fs.String("exploits-dir", "bench/exploits", "where recorded winning exploits are cached")
	ledger := fs.String("ledger", "bench/defense-xbow-ledger.jsonl", "append-only defense ledger")
	out := fs.String("out", "", "also write the by-category scoreboard markdown here")
	patchFile := fs.String("patch-file", "", "DEV/CI: supply the engineer's patch from a file (FILE-block format) instead of the LLM — validates the pipeline deterministically with no model")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	benches, err := bench.LoadXBOWSuite(*suite)
	if err != nil {
		return fmt.Errorf("load suite: %w", err)
	}
	benches = filterXBOWDefense(benches, *only, *category)
	if len(benches) == 0 {
		return fmt.Errorf("no benchmarks matched --only/--category")
	}

	// The engineer's patch source. Normally the LLM (the customer's key in prod, the proxy in dev); the
	// --patch-file affordance supplies a fixed patch so the MECHANICAL pipeline (build→apply→rebuild→
	// replay→regression) can be validated with no model (CI + demo). No LLM and no patch-file → fail loud,
	// never a fabricated run (§10).
	patchFn, model, perr := resolvePatcher(*patchFile)
	if perr != nil {
		return perr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var results []bench.XBOWDefenseResult
	for _, b := range benches {
		r := runOneXBOWDefense(ctx, b, *binary, *timeout, *targetPort, *exploitsDir, patchFn)
		fmt.Printf("[defense-xbow] %-16s %-14s %s\n", r.BenchmarkID, r.Verdict, r.Note)
		e := bench.XBOWDefenseLedgerEntry{
			TS: time.Now().UTC().Format(time.RFC3339), BenchmarkID: r.BenchmarkID, Class: r.Class,
			Level: r.Level, Verdict: r.Verdict, Remediated: r.Remediated(), Model: model, Note: r.Note,
		}
		if aerr := bench.AppendXBOWDefenseLedger(*ledger, e); aerr != nil {
			fmt.Fprintf(os.Stderr, "[defense-xbow] ledger append: %v\n", aerr)
		}
		results = append(results, r)
	}
	sb := bench.AggregateXBOWDefense(results)
	fmt.Print("\n" + bench.RenderXBOWDefenseScoreboard(sb))
	if *out != "" {
		if werr := os.WriteFile(*out, []byte(bench.RenderXBOWDefenseScoreboard(sb)), 0o644); werr != nil { //nolint:gosec // bench artifact
			return werr
		}
	}
	return nil
}

// patcherFn is the engineer's patch source: the LLM in production, or a fixed file for pipeline validation.
type patcherFn func(ctx context.Context, f codeagent.Finding, sources []codeagent.SourceFile) (codeagent.Patch, error)

// resolvePatcher builds the patch source. --patch-file → a fixed parsed patch (no model); else the LLM
// from env (proxy/customer key). Neither → a loud error (never a fabricated run, §10).
func resolvePatcher(patchFile string) (patcherFn, string, error) {
	if strings.TrimSpace(patchFile) != "" {
		raw, err := os.ReadFile(patchFile) //nolint:gosec // operator-supplied dev/CI patch
		if err != nil {
			return nil, "", fmt.Errorf("read --patch-file: %w", err)
		}
		files, perr := codeagent.ParsePatch(string(raw))
		if perr != nil {
			return nil, "", fmt.Errorf("parse --patch-file: %w", perr)
		}
		fn := func(context.Context, codeagent.Finding, []codeagent.SourceFile) (codeagent.Patch, error) {
			return codeagent.Patch{Files: files, Raw: string(raw)}, nil
		}
		return fn, "patch-file", nil
	}
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		return nil, "", fmt.Errorf("defense-xbow needs an LLM (the engineer's brain): set LLM_BASE_URL=http://127.0.0.1:8899/v1 LLM_MODEL=<m> LLM_API_KEY=<k> (the proxy), or ANTHROPIC_API_KEY for a frontier model — or pass --patch-file to validate the pipeline with a fixed patch")
	}
	fn := func(ctx context.Context, f codeagent.Finding, sources []codeagent.SourceFile) (codeagent.Patch, error) {
		return codeagent.ProposePatch(ctx, llm, f, sources)
	}
	return fn, firstNonEmptyEnv("LLM_MODEL", "ANTHROPIC_MODEL"), nil
}

// runOneXBOWDefense executes the full defense flow for one challenge in an isolated temp copy.
func runOneXBOWDefense(ctx context.Context, b bench.XBOWBenchmark, binary, timeout, targetPort, exploitsDir string, patch patcherFn) bench.XBOWDefenseResult {
	res := bench.XBOWDefenseResult{BenchmarkID: b.ID, Level: b.Config.Level}
	if len(b.Config.Tags) > 0 {
		res.Class = b.Config.Tags[0]
	}
	errored := func(note string) bench.XBOWDefenseResult { res.Verdict = bench.DefErrored; res.Note = note; return res }

	// 1. Isolate: copy the benchmark dir to a temp working copy so we NEVER modify the shared suite (the
	//    other session builds the same suite). Deleted on return — one copy at a time (disk).
	work, cleanup, cerr := copyBenchmarkDir(b.Dir)
	if cerr != nil {
		return errored("copy benchmark: " + cerr.Error())
	}
	defer cleanup()
	compose := composeIn(work)
	if compose == "" {
		return errored("no docker-compose in the copied benchmark dir")
	}

	// 2. Build + up the VULN app (unique flag) and confirm exploitability by capturing the flag, recording
	//    the winning exploit for deterministic replay.
	flagStr, _ := bench.GenerateFlag()
	if o, e := compose_(ctx, compose, "build", "--build-arg", "FLAG="+flagStr, "--build-arg", "flag="+flagStr); e != nil {
		return errored("vuln build failed: " + tail(o))
	}
	if o, e := compose_(ctx, compose, "up", "-d", "--wait"); e != nil {
		_, _ = composeDown(ctx, compose, true)
		return errored("vuln up failed: " + tail(o))
	}
	defer func() { _, _ = composeDown(ctx, compose, true) }() // down + rmi local (disk)

	target := targetURL(ctx, compose, targetPort)
	if target == "" {
		return errored("could not determine target URL")
	}

	exploit, captured, note := attackAndRecordExploit(ctx, binary, timeout, target, flagStr, b, exploitsDir)
	if !captured {
		res.Verdict = bench.DefNotVulnerable
		res.Note = "could not capture the flag on the vuln build — no exploit to defend against (" + note + ")"
		return res
	}
	res.VulnConfirmed = true

	// 3. Engineer patches: hand it the finding + source, get whole-file replacements.
	sources := gatherSource(work)
	finding := codeagent.Finding{Class: res.Class, Endpoint: exploit.Steps[0].Path,
		Detail: fmt.Sprintf("the pentest captured the flag via: %s %s %s", exploit.Steps[0].Method, exploit.Steps[0].Path, exploit.Steps[0].Body)}
	proposed, perr := patch(ctx, finding, sources)
	if perr != nil {
		res.Note = "patch proposal error: " + perr.Error()
	}
	if proposed.Empty() {
		res.Verdict = bench.DefNoPatch
		res.Note = "the engineer produced no applicable patch"
		return res
	}
	res.Patched = true

	// 4. Apply the patch to the temp copy + REBUILD. A patch that won't build broke the app.
	if aerr := applyPatch(work, proposed.Files); aerr != nil {
		return errored("apply patch: " + aerr.Error())
	}
	if o, e := compose_(ctx, compose, "build", "--build-arg", "FLAG="+flagStr, "--build-arg", "flag="+flagStr); e != nil {
		res.Verdict = bench.DefBrokeApp
		res.Note = "patched build failed (the fix doesn't compile/build): " + tail(o)
		return res
	}
	if o, e := compose_(ctx, compose, "up", "-d", "--wait", "--force-recreate"); e != nil {
		res.Verdict = bench.DefBrokeApp
		res.Note = "patched app did not come up (the fix broke startup): " + tail(o)
		return res
	}
	target = targetURL(ctx, compose, targetPort)

	// 5. Verify: replay the recorded exploit (still capturable?) + the regression guard (app still works?).
	rctx, rcancel := context.WithTimeout(ctx, 90*time.Second)
	defer rcancel()
	flagSeen, replayErr := bench.ReplayExploit(rctx, httpClient(), target, exploit, flagStr)
	if replayErr != nil {
		return errored("replay error (app unreachable after patch): " + replayErr.Error())
	}
	res.ExploitFailsAfterPatch = !flagSeen
	// App is functional only if the homepage serves AND any declared legitimate probe still works (the
	// latter hardens the guard for access-control fixes that could "close" the exploit by breaking all use).
	res.AppFunctionalAfterPatch = bench.AppFunctional(rctx, httpClient(), target) &&
		bench.FunctionalPreserved(rctx, httpClient(), target, exploit)
	res.Grade()
	res.Note = fmt.Sprintf("exploit_fails=%v app_ok=%v (%d source file(s) patched)",
		res.ExploitFailsAfterPatch, res.AppFunctionalAfterPatch, len(proposed.Files))
	return res
}
