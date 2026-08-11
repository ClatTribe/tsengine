package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// triageCmd runs the T1 triage benchmark — the task a security engineer spends most of the week on,
// and the one that had no number until now.
func triageCmd(argv []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	agent := fs.Bool("agent", false, "also run the configured LLM and print the substrate→agent delta")
	label := fs.String("label", "", "label for the LLM arm (e.g. the model name)")
	out := fs.String("out", "", "also write the rendered table to this path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx := context.Background()
	cases := bench.TriageCases()

	var scores []bench.TriageScore
	for _, e := range []bench.Triager{bench.SeverityTriager{}, bench.PathHeuristicTriager{}} {
		s, _, err := bench.ScoreTriage(ctx, e, cases)
		if err != nil {
			return err
		}
		scores = append(scores, s)
	}

	if *agent {
		llm, ok := cloudengine.LLMFromEnv()
		if !ok {
			fmt.Fprintln(os.Stderr, "[--agent] no LLM configured — the substrate numbers above stand")
		} else {
			lbl := *label
			if lbl == "" {
				lbl = strings.TrimSpace(os.Getenv("LLM_MODEL"))
			}
			s, misses, err := bench.ScoreTriage(ctx, bench.LLMTriager{LLM: llm, Label: lbl}, cases)
			if err != nil {
				return err
			}
			scores = append(scores, s)
			if len(misses) > 0 {
				fmt.Fprintln(os.Stderr, "\nwhere the model went wrong:")
				for _, m := range misses {
					fmt.Fprintln(os.Stderr, "  "+m)
				}
			}
		}
	}

	table := bench.RenderTriageScores(scores)
	fmt.Print(table)
	// Only meaningful when an agent arm actually ran — otherwise it would compare a baseline to itself.
	if len(scores) >= 3 {
		best := scores[len(scores)-1]
		base := scores[1] // the stronger deterministic baseline
		fmt.Printf("\n## Ablation — triage lift (%s → %s)\n", base.Engine, best.Engine)
		fmt.Printf("Youden J:  %.2f → %.2f (Δ %+.2f)\n", base.Youden(), best.Youden(), best.Youden()-base.Youden())
		fmt.Printf("recall:    %.2f → %.2f\n", base.Recall(), best.Recall())
		fmt.Printf("restraint: %.2f → %.2f\n", base.Restraint(), best.Restraint())
	}
	if *out != "" {
		if werr := os.WriteFile(*out, []byte(table), 0o644); werr != nil { //nolint:gosec // bench artifact
			return werr
		}
	}
	return nil
}
