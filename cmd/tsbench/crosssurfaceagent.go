package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// crossSurfaceAgentCmd runs the AI Security Engineer twice over one cross-asset fixture — blind to
// code, then with the joined estate — and reports whether seeing the second surface lets it tell the
// chain the first cannot. This is the wedge capability (code→cloud) measured with a model in the
// loop; ScoreCrossSurface measures only whether the DATA supports the conclusion.
func crossSurfaceAgentCmd(argv []string) error {
	fs := flag.NewFlagSet("crosssurface-agent", flag.ContinueOnError)
	scenario := fs.String("scenario", "leaked-key", "fixture: leaked-key (code→cloud) | web-host (web→cloud)")
	maxIters := fs.Int("max-iters", 24, "agent tool-call budget per arm")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	var fx bench.CrossSurfaceFixture
	switch *scenario {
	case "leaked-key":
		fx = bench.LeakedKeyToCloudCrown()
	case "web-host":
		fx = bench.WebHostToCloudCrown()
	default:
		return fmt.Errorf("unknown scenario %q (leaked-key|web-host)", *scenario)
	}

	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		// Honest: report the substrate floor, and say plainly that the agent was not evaluated.
		fmt.Print(bench.RenderCrossSurface(bench.ScoreCrossSurface(fx)))
		fmt.Fprintln(os.Stderr, "\nNO LLM CONFIGURED — the substrate floor above is real, but the AGENT was not\n"+
			"evaluated. Set TSENGINE_LLM_OPENCODE / ANTHROPIC_API_KEY / LLM_BASE_URL to measure the wedge.")
		return nil
	}

	res := bench.RunCrossSurfaceAgent(context.Background(), fx, llm, *maxIters)
	fmt.Print(bench.RenderCrossSurfaceAgent(res))
	return nil
}
