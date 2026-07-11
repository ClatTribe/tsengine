package main

import (
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// scorecardCmd renders the unified 4-shared-public-benchmark scorecard vs SOTA.
func scorecardCmd(argv []string) error {
	fs := flag.NewFlagSet("scorecard", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	fmt.Print(bench.RenderFullScorecard())
	return nil
}
