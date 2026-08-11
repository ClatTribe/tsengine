package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// scorecardCmd prints the composite AI-Security-Engineer efficacy number against the 40% bar, with
// the measurement gaps stated as loudly as the scores.
func scorecardCmd(argv []string) error {
	fs := flag.NewFlagSet("scorecard", flag.ContinueOnError)
	out := fs.String("out", "", "also write the rendered scorecard to this path")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	md := bench.RenderEngineerScorecard(bench.EngineerScorecard())
	fmt.Print(md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil { //nolint:gosec // bench artifact
			return err
		}
	}
	return nil
}
