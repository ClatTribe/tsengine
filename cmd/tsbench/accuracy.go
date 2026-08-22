package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ClatTribe/tsengine/internal/accuracybench"
)

// accuracyCmd renders the deterministic cores' FP/FN scorecard.
//
// internal/accuracybench calls itself "a single runnable, CI-gateable report" and nothing ran it —
// it had no caller at all, so the aggregate it exists to produce was never produced.
//
// READ THE NUMBER CORRECTLY. Every core scores against a corpus WE wrote, so a perfect column
// measures whether the fixtures and the code agree — not whether the product works (§14.2.5). Two
// external answer keys put the same class of capability at roughly two thirds: BishopFox
// IAM-Vulnerable 64.5%, RhinoSecurityLabs' GCP catalogue 65.2%. This scorecard's job is REGRESSION
// detection — noticing when a core that used to classify a case correctly stops — and it is not
// evidence of efficacy. The gate in internal/accuracybench enforces exactly that reading.
func accuracyCmd(argv []string) error {
	fs := flag.NewFlagSet("accuracy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	scores := accuracybench.Run()
	fmt.Print(accuracybench.Render(scores))
	return regressionError(scores)
}

// EVERY regressed core is named, not the first.
//
// Returning on the first one made the second invisible until the first was fixed — a silent
// truncation of the very report the command exists to give, and the same "no silent caps" rule
// §14.2 applies to benchmarks. An operator should learn the whole extent of a regression in one
// run, not discover it a core at a time.
// regressionError names every core that fell below the bar, or nil when none did. Extracted so the
// "name them all" property is testable without running the whole scorecard.
func regressionError(scores []accuracybench.CoreScore) error {
	var regressed []string
	for _, s := range scores {
		if !s.Perfect() {
			regressed = append(regressed,
				fmt.Sprintf("%s (recall %.2f, precision %.2f over %d cases)", s.Core, s.Recall, s.Precision, s.Cases))
		}
	}
	if len(regressed) > 0 {
		return fmt.Errorf("%d core(s) regressed:\n  %s", len(regressed), strings.Join(regressed, "\n  "))
	}
	return nil
}
