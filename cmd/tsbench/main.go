// Command tsbench is the L1 benchmark harness CLI. It runs the real
// tsengine binary against a fixture, scores the output, and prints a
// report that always cites the neutral competitor leaderboard
// (CLAUDE.md §14).
//
//	tsbench run      --fixture <path> [--trials N] [--binary ./bin/tsengine] [--image ref]
//	tsbench ablation --fixture <path> [--trials N]   # L1.5 on vs off
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClatTribe/tsengine/internal/bench"
)

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "run":
		if err := runCmd(args[1:], false); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench run: %v\n", err)
			os.Exit(1)
		}
	case "ablation":
		if err := runCmd(args[1:], true); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench ablation: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "tsbench: unknown subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `tsbench — tsengine L1 benchmark harness

Usage:
  tsbench run      --fixture <path> [--trials N] [--binary <path>] [--image <ref>]
  tsbench ablation --fixture <path> [--trials N]

Fixtures live under fixtures/. Stub fixtures (runnable:false) need their
corpus deployed out-of-band (WAVSEP webapp, OWASP BenchmarkJava tree).
`)
}

func runCmd(argv []string, ablation bool) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fixturePath := fs.String("fixture", "", "path to fixture dir or fixture.json")
	trials := fs.Int("trials", 1, "trial count (median + p10/p90 over N)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "300s", "per-scan timeout")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *fixturePath == "" {
		return fmt.Errorf("--fixture is required")
	}

	f, err := bench.Load(*fixturePath)
	if err != nil {
		return err
	}

	if !f.Runnable {
		// Stub fixture: print its competitor numbers + why it can't run.
		fmt.Print(bench.RenderStub(f))
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 30*time.Minute)
	defer cancelT()

	opts := bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout, Trials: *trials}

	if ablation {
		a, err := bench.RunAblation(ctx, f, opts)
		if err != nil {
			return err
		}
		fmt.Print(bench.Render(f, a.Enabled))
		fmt.Print(bench.RenderAblation(f, a))
		if !a.Enabled.AllPass {
			os.Exit(3)
		}
		return nil
	}

	res, err := bench.Run(ctx, f, opts)
	if err != nil {
		return err
	}
	fmt.Print(bench.Render(f, res))
	if !res.AllPass {
		os.Exit(3)
	}
	return nil
}
