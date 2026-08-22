package main

import (
	"flag"
	"fmt"
	"os"

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
	for _, s := range scores {
		if !s.Perfect() {
			// A regression is a non-zero exit so CI can gate on it, and it names the core rather
			// than only failing: "accuracy dropped" without a name is a message nobody can act on.
			return fmt.Errorf("core %q regressed (recall %.2f, precision %.2f)", s.Core, s.Recall, s.Precision)
		}
	}
	return nil
}
