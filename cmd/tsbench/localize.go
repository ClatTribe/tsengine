package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// localize.go is the `tsbench localize` subcommand — the Vulnerability-Localization benchmark runner
// (Antares lineage) AND an ad-hoc "where is the sink in THIS repo?" tool.
//
//   - Benchmark mode (default): runs the built-in synthetic corpus with the LLM-free HeuristicLocalizer
//     and prints recall@{1,3,5} + MRR. With --agent it also runs the LLMLocalizer and prints the
//     substrate→agent ablation (the model's measured localization lift). No key needed for the baseline.
//   - Repo mode (--repo <dir> --cwe CWE-89): localizes a real source tree for one class and prints the
//     ranked candidates with their file:line evidence + the exploration trace.
func localizeCmd(argv []string) error {
	fs := flag.NewFlagSet("localize", flag.ContinueOnError)
	agent := fs.Bool("agent", false, "also run the LLM localizer (cloudengine.LLMFromEnv) and the substrate-vs-agent ablation")
	repoDir := fs.String("repo", "", "localize a real repo directory instead of the built-in corpus (requires --cwe)")
	cwe := fs.String("cwe", "", "CWE to localize when --repo is set, e.g. CWE-89")
	desc := fs.String("desc", "", "optional vuln description/title when --repo is set (adds keyword signal)")
	out := fs.String("out", "", "also write the rendered scoreboard markdown to this path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx := context.Background()

	if *repoDir != "" {
		if *cwe == "" {
			return fmt.Errorf("--repo requires --cwe (e.g. --cwe CWE-89)")
		}
		repo, err := codelocalize.LoadRepo(*repoDir, codelocalize.LoadOptions{})
		if err != nil {
			return err
		}
		res, err := repoLocalizer(*agent).Localize(ctx, codelocalize.Query{CWE: []string{*cwe}, Description: *desc}, repo)
		if err != nil {
			return err
		}
		fmt.Printf("engine: %s  files scanned: %d\n", res.Engine, len(repo))
		for _, s := range res.Trace {
			fmt.Printf("  · %s\n", s)
		}
		if len(res.Ranked) == 0 {
			fmt.Println("ranked candidates: (clean — no sink evidence for this class)")
			return nil
		}
		fmt.Println("ranked candidates:")
		for i, c := range res.Ranked {
			fmt.Printf("  %2d. %-44s score=%.1f conf=%.2f\n", i+1, c.Path, c.Score, c.Confidence)
			for _, r := range c.Reasons {
				fmt.Printf("        %s\n", r)
			}
		}
		return nil
	}

	scenarios := bench.LocalizeScenarios()
	base, err := bench.RunLocalize(ctx, codelocalize.HeuristicLocalizer{}, scenarios)
	if err != nil {
		return err
	}
	report := bench.RenderLocalize(base)
	fmt.Print(report)

	if *agent {
		llm, ok := cloudengine.LLMFromEnv()
		if !ok {
			fmt.Fprintln(os.Stderr, "\n[--agent] no LLM configured (set LLM_API_KEY, or an Ollama host) — skipping the agent ablation; the substrate numbers above stand")
		} else {
			agentScores, err := bench.RunLocalize(ctx, codelocalize.LLMLocalizer{LLM: llm}, scenarios)
			if err != nil {
				return err
			}
			ablation := bench.RenderLocalizeAblation(base, agentScores)
			fmt.Print("\n", bench.RenderLocalize(agentScores), "\n", ablation)
			report += "\n" + bench.RenderLocalize(agentScores) + "\n" + ablation
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// repoLocalizer picks the localizer for ad-hoc repo mode: the LLM tier when --agent is set AND a model
// is configured, else the deterministic heuristic (never a falsely-confident LLM-only path).
func repoLocalizer(agent bool) codelocalize.Localizer {
	if agent {
		if llm, ok := cloudengine.LLMFromEnv(); ok {
			return codelocalize.LLMLocalizer{LLM: llm}
		}
	}
	return codelocalize.HeuristicLocalizer{}
}
