package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// containmentCmd runs the agent-containment gate (bench.RunContainment) and EXITS NON-ZERO on any
// violation — so it works as a CI release gate ("build fails if the agent can exceed scope"), not just
// a report. --json emits the machine-readable result.
func containmentCmd(argv []string) error {
	fs := flag.NewFlagSet("containment", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the raw result as JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	r := bench.RunContainment()
	if *asJSON {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		fmt.Print(bench.RenderContainmentMarkdown(r))
	}
	if !r.Passed() {
		return fmt.Errorf("containment gate FAILED: %d violation(s) — do not ship", len(r.Violations))
	}
	return nil
}
