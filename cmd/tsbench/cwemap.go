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

// cwemapCmd runs the CWE-attribution benchmark — the ANALYSIS lane.
//
// The localization bench measures code navigation, where a general model wins. This measures security
// KNOWLEDGE: name the weakness class from raw scanner output that carries no CWE. It is the task a
// security-specialized model should be best at, and it maps to a real product gap (§8's compliance
// hook keys on CWE, so an unattributed finding gets no control mapping).
func cwemapCmd(argv []string) error {
	fs := flag.NewFlagSet("cwemap", flag.ContinueOnError)
	agent := fs.Bool("agent", false, "also run the configured LLM (cloudengine.LLMFromEnv) and print the substrate→agent delta")
	label := fs.String("label", "", "label for the LLM arm in the table (e.g. the model name)")
	out := fs.String("out", "", "also write the rendered table to this path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ctx := context.Background()
	cases := bench.CWECases()

	base, err := bench.ScoreCWE(ctx, bench.KeywordCWEAttributor{}, cases)
	if err != nil {
		return err
	}
	scores := []bench.CWEScore{base}

	if *agent {
		llm, ok := cloudengine.LLMFromEnv()
		if !ok {
			fmt.Fprintln(os.Stderr, "[--agent] no LLM configured (set LLM_BASE_URL + LLM_MODEL, or an API key) — substrate numbers above stand")
		} else {
			lbl := *label
			if lbl == "" {
				lbl = strings.TrimSpace(os.Getenv("LLM_MODEL"))
			}
			if lbl == "" {
				lbl = "llm"
			}
			s, aerr := bench.ScoreCWE(ctx, bench.LLMCWEAttributor{LLM: llm, Label: lbl}, cases)
			if aerr != nil {
				return aerr
			}
			scores = append(scores, s)
		}
	}

	table := bench.RenderCWEScores(scores)
	fmt.Print(table)

	if len(scores) == 2 {
		a, b := scores[0], scores[1]
		fmt.Printf("\n## Ablation — knowledge lift (substrate → %s)\n", b.Engine)
		fmt.Printf("accuracy:  %.2f → %.2f (Δ %+.2f)\n", a.Accuracy(), b.Accuracy(), b.Accuracy()-a.Accuracy())
		fmt.Printf("restraint: %.2f → %.2f (Δ %+.2f)\n", a.Restraint(), b.Restraint(), b.Restraint()-a.Restraint())
		if b.Unparseable > 0 {
			fmt.Printf("\nNOTE: %d/%d responses were unparseable — that is a FORMAT weakness, not a knowledge\n", b.Unparseable, b.Total)
			fmt.Printf("weakness, and it depresses accuracy. Read the two separately before concluding.\n")
		}
	}

	if *out != "" {
		if werr := os.WriteFile(*out, []byte(table), 0o644); werr != nil {
			return werr
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	}
	return nil
}
