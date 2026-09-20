package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/rlvr"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// armSpecGen resolves the --arm flag to a proposer. substrate = the deterministic HeuristicSpecGen
// (no model, the ablation control); model = the pentester's own D-agent (pentest.SpecGenFor over a
// live LLM from cloudengine.LLMFromEnv — a cloud key, an OpenAI-compat endpoint, or a local/served
// tuned model). The model arm fails LOUD when no model is configured, rather than silently falling
// back to the substrate — a silent fallback would report the substrate's number under the model's
// name, the exact false-attribution the ablation exists to prevent.
func armSpecGen(ctx context.Context, arm string) (rlvr.SpecGen, error) {
	switch arm {
	case "", "substrate":
		return rlvr.SubstrateSpecGen(), nil
	case "model":
		llm, ok := cloudengine.LLMFromEnv()
		if !ok {
			return nil, fmt.Errorf("--arm model needs a model configured (LLM_API_KEY, an OpenAI-compat endpoint, or a local Ollama) — none found; set one or use --arm substrate")
		}
		fmt.Fprintln(os.Stderr, "rlvr: model arm — proposing with the live D-agent (pentest.LLMSpecGen, no heuristic fallback)")
		return rlvr.AgentSpecGen(ctx, llm), nil
	default:
		return nil, fmt.Errorf("unknown --arm %q (want substrate|model)", arm)
	}
}

// rlvr.go is the `tsbench rlvr` subcommand — the reward-predicate harness for RL-with-verifiable-
// rewards over exploit-verification (does a model-proposed exploitation predicate actually hold
// against the target, or is it a hallucination?). It exercises internal/rlvr end to end and is the
// bootstrap for tuning a verifier model:
//
//   - selftest (default): a self-contained demo — seeds episodes from synthetic findings via the
//     deterministic SubstrateSpecGen, grades them against a built-in reference target that models
//     one genuinely-vulnerable and one patched host, and prints the scorecard. Needs no inputs and
//     no network, so it runs in CI. --write-fixture <dir> captures the run to a corpus + cassette.
//   - score: replays a checked-in cassette against a checked-in episode corpus offline and prints
//     the scorecard. The reproducible train/eval path — the same episodes re-grade identically
//     forever because the recorded responses are the fixed bytes the predicate disposes over.
//   - capture: runs live against a real target (a vulhub container) with the product's HTTPProber,
//     records a cassette, and emits the graded corpus. The gated half (needs an authorized target).
//
// The headline the runner prints is SPECIFICITY, not accuracy: the value of a verifier is that it
// says "no" correctly to a fake exploit, so the FP-rejection rate over patched targets is the
// number that governs whether it is shippable (§14.2 rule 5).
func rlvrCmd(argv []string) error {
	sub := "selftest"
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		sub, argv = argv[0], argv[1:]
	}
	switch sub {
	case "selftest":
		return rlvrSelftest(argv)
	case "score":
		return rlvrScore(argv)
	case "capture":
		return rlvrCapture(argv)
	default:
		return fmt.Errorf("unknown rlvr subcommand %q (want selftest|score|capture)", sub)
	}
}

// demoCorpus builds the built-in episodes: one truly-vulnerable SSTI host and one patched one.
// Both are SSTI so SubstrateSpecGen (HeuristicSpecGen) proposes an eval_arithmetic spec for each;
// the reference target decides whether the injected expression is evaluated. The patched case is
// the FP-control: a correct verifier must NOT call it exploited.
func demoCorpus() []rlvr.Episode {
	mk := func(id, host string, truth rlvr.Truth) rlvr.Episode {
		f := types.Finding{
			Title:    "Server-Side Template Injection",
			CWE:      []string{"CWE-1336"},
			Endpoint: "http://" + host + "/render?tpl=x",
		}
		ep, ok := rlvr.SeedEpisode(id, host, f, truth, "cx-"+id, rlvr.SubstrateSpecGen())
		if !ok {
			panic("demo finding failed to seed — HeuristicSpecGen regressed on SSTI")
		}
		return ep
	}
	return []rlvr.Episode{
		mk("ssti-vuln", "vuln.demo", rlvr.TruthVulnerable),
		mk("ssti-patched", "patched.demo", rlvr.TruthPatched),
	}
}

// referenceProber models the demo targets deterministically: a probe to vuln.demo EVALUATES the
// injected arithmetic (returns the product), a probe to patched.demo ECHOES the literal expression
// (never evaluates it). Any other host is unreachable → Ungradeable, so a corpus pointed at a host
// the reference does not model is honestly dropped, not silently graded.
type referenceProber struct{}

func (referenceProber) Send(_ context.Context, p pentest.Probe) (pentest.ProbeResult, error) {
	const product, expr = "1022117", "{{1009*1013}}"
	switch {
	case strings.Contains(p.URL, "vuln.demo"):
		return pentest.ProbeResult{Status: 200, Body: "rendered: " + product}, nil
	case strings.Contains(p.URL, "patched.demo"):
		return pentest.ProbeResult{Status: 200, Body: "rendered: " + expr}, nil // echoed, not evaluated
	default:
		return pentest.ProbeResult{}, fmt.Errorf("reference target has no host for %s", p.URL)
	}
}

func rlvrSelftest(argv []string) error {
	fs := flag.NewFlagSet("rlvr selftest", flag.ContinueOnError)
	writeFixture := fs.String("write-fixture", "", "capture this run to <dir>/corpus.json + <dir>/cassette.json")
	arm := fs.String("arm", "substrate", "proposer arm: substrate (heuristic, no model) | model (the D-agent over LLM_API_KEY)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx := context.Background()
	gen, err := armSpecGen(ctx, *arm)
	if err != nil {
		return err
	}
	eps := demoCorpus()

	// Grade through a Recorder so the same run can be dumped as a replayable cassette. RunArm
	// re-proposes each episode's spec with the chosen arm against the reference target — which
	// answers any probe to the demo hosts, so the model arm is fully gradeable here with just a key.
	rec := rlvr.NewRecorder(referenceProber{})
	graded, conf := rlvr.RunArm(ctx, rec, nil, nil, eps, gen)
	printScorecard(graded, conf)

	if *writeFixture != "" {
		if err := os.MkdirAll(*writeFixture, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(*writeFixture, "corpus.json"), eps); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(*writeFixture, "cassette.json"), rec.Cassette()); err != nil {
			return err
		}
		fmt.Printf("\nwrote fixture: %s/{corpus.json,cassette.json}\n", *writeFixture)
	}
	return nil
}

func rlvrScore(argv []string) error {
	fs := flag.NewFlagSet("rlvr score", flag.ContinueOnError)
	corpus := fs.String("corpus", "fixtures/rlvr/corpus.json", "episode corpus (JSON array of rlvr.Episode)")
	cassette := fs.String("cassette", "fixtures/rlvr/cassette.json", "recorded responses (rlvr.Cassette JSON)")
	outJSONL := fs.String("out", "", "also write the graded episodes as JSONL to this path")
	arm := fs.String("arm", "substrate", "proposer arm: substrate (matches the recorded cassette) | model (the D-agent; probes it proposes that are absent from the cassette grade Ungradeable — capture against a live target for full model-arm numbers)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx := context.Background()
	gen, err := armSpecGen(ctx, *arm)
	if err != nil {
		return err
	}
	var eps []rlvr.Episode
	if err := readJSON(*corpus, &eps); err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	var cas rlvr.Cassette
	if err := readJSON(*cassette, &cas); err != nil {
		return fmt.Errorf("read cassette: %w", err)
	}
	graded, conf := rlvr.RunArm(ctx, rlvr.NewReplayer(cas), nil, nil, eps, gen)
	printScorecard(graded, conf)
	if *outJSONL != "" {
		f, err := os.Create(*outJSONL)
		if err != nil {
			return err
		}
		defer f.Close()
		return rlvr.WriteJSONL(f, graded)
	}
	return nil
}

func rlvrCapture(argv []string) error {
	fs := flag.NewFlagSet("rlvr capture", flag.ContinueOnError)
	corpus := fs.String("corpus", "", "episode corpus to run live (JSON array of rlvr.Episode)")
	outCassette := fs.String("out-cassette", "", "write the captured cassette here (replayable offline)")
	outJSONL := fs.String("out", "", "write the graded episodes as JSONL here")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *corpus == "" {
		return fmt.Errorf("capture requires --corpus (episodes with the targets to probe live)")
	}
	var eps []rlvr.Episode
	if err := readJSON(*corpus, &eps); err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	// The product's own benign prober, wrapped so the live run is captured for offline replay.
	// Reached only against an authorized target — the caller owns that authorization (the same
	// gate as any active probe).
	rec := rlvr.NewRecorder(pentest.NewHTTPProber())
	graded, conf := rlvr.Run(context.Background(), rec, nil, nil, eps)
	printScorecard(graded, conf)
	if *outCassette != "" {
		if err := writeJSON(*outCassette, rec.Cassette()); err != nil {
			return err
		}
	}
	if *outJSONL != "" {
		f, err := os.Create(*outJSONL)
		if err != nil {
			return err
		}
		defer f.Close()
		return rlvr.WriteJSONL(f, graded)
	}
	return nil
}

// printScorecard renders the confusion matrix (specificity first) plus a per-episode line.
func printScorecard(graded []rlvr.Graded, conf rlvr.Confusion) {
	fmt.Println("tsbench rlvr — exploit-verification scorecard")
	fmt.Println(conf.Report())
	fmt.Println()
	for _, g := range graded {
		label := map[rlvr.Truth]string{rlvr.TruthVulnerable: "vulnerable", rlvr.TruthPatched: "patched", rlvr.TruthUnknown: "unlabeled"}[g.Episode.Truth]
		fmt.Printf("  %-16s truth=%-10s verdict=%-13s reward=%.0f\n", g.Episode.ID, label, g.Verdict, g.Reward)
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// 0o600: a cassette/episode file can carry probe responses from a live target, so it is owner-only
	// (and gosec G306 requires <= 0o600 regardless).
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
