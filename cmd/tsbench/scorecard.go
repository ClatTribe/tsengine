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

// autonomyCmd renders the AUTONOMY report — the share of both jobs that runs without a human handing
// the agent something.
//
// Separate from `scorecard` on purpose. That one asks whether the OUTPUT is good enough; this asks who
// does the WORK. A task can score 1.00 and still make a person type its inputs every time, and only one
// of those two questions tells you whether you have an engineer or a tool.
func autonomyCmd(argv []string) error {
	fs := flag.NewFlagSet("autonomy", flag.ContinueOnError)
	out := fs.String("out", "", "also write the rendered report to this path")
	job := fs.String("job", "", "limit to one job: engineer | pentester")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	tasks := bench.AllAutonomyTasks()
	switch *job {
	case "engineer":
		tasks = bench.EngineerAutonomy()
	case "pentester":
		tasks = bench.PentesterAutonomy()
	case "":
	default:
		return fmt.Errorf("unknown --job %q (expected engineer or pentester)", *job)
	}
	md := bench.RenderAutonomy(tasks)
	fmt.Print(md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil { //nolint:gosec // bench artifact
			return err
		}
	}
	return nil
}
