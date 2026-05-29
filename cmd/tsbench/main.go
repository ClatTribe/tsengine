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
	case "wavsep":
		if err := wavsepCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench wavsep: %v\n", err)
			os.Exit(1)
		}
	case "sast":
		if err := sastCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench sast: %v\n", err)
			os.Exit(1)
		}
	case "cloud":
		if err := cloudCmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "tsbench cloud: %v\n", err)
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
  tsbench wavsep   --target <url> --ground-truth <expected-cases.csv> [--image <ref>]
  tsbench sast     --target <src-dir> --ground-truth <expectedresults.csv> [--image <ref>]
  tsbench cloud    --target <provider> --ground-truth <expected-controls.csv> [--image <ref>]

Fixtures live under fixtures/. Stub fixtures (runnable:false) need their
corpus deployed out-of-band (WAVSEP webapp, OWASP BenchmarkJava tree).

sast scans a source tree (e.g. the OWASP BenchmarkJava source, extracted from
the strix-bench/owasp-benchmark image) with the repository asset and scores
per-CWE-category Youden vs the SAST leaderboard (Veracode/Checkmarx/Fortify).

cloud scans a cloud account (--target aws|gcp|azure) with the cloud_account
asset (prowler + scoutsuite) and scores per-CIS-section recall against a mock
account seeded with a known-failing posture. Scoped, short-lived credentials
are read from the environment (AWS_*/GOOGLE_*/AZURE_*) and forwarded into the
sandbox — never written to disk. No neutral CSPM leaderboard (Prowler/Scout
Suite/Wiz/Orca self-publish), so the cite is the CIS-recall reference.
`)
}

// wavsepCmd runs the WAVSEP DAST benchmark: scan the deployed WAVSEP root
// (katana crawls the test-case URLs, the fan-out scans them), then score
// per-category Youden against the ground-truth CSV. Needs the WAVSEP
// webapp reachable + the sandbox image built with katana.
func wavsepCmd(argv []string) error {
	fs := flag.NewFlagSet("wavsep", flag.ContinueOnError)
	target := fs.String("target", "", "deployed WAVSEP root URL (e.g. http://host.docker.internal:8098/wavsep/)")
	groundTruth := fs.String("ground-truth", "", "path to expected-cases.csv (WAVSEP ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (WAVSEP is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *target == "" || *groundTruth == "" {
		return fmt.Errorf("--target and --ground-truth are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunWavsep(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderWavsep(rep))
	return nil
}

// sastCmd runs the OWASP Benchmark v1.2 SAST benchmark: scan a source tree
// (the BenchmarkJava tree — extract it from the strix-bench/owasp-benchmark
// image or clone it) with the repository asset, then score per-CWE-category
// Youden against expectedresults*.csv vs the SAST leaderboard.
func sastCmd(argv []string) error {
	fs := flag.NewFlagSet("sast", flag.ContinueOnError)
	target := fs.String("target", "", "path to the SAST benchmark source tree (e.g. BenchmarkJava)")
	groundTruth := fs.String("ground-truth", "", "path to expectedresults*.csv (OWASP Benchmark ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (the tree is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *target == "" || *groundTruth == "" {
		return fmt.Errorf("--target and --ground-truth are required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunSast(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderSast(rep))
	return nil
}

// cloudCmd runs the CIS AWS Foundations CSPM benchmark: scan a cloud account
// (--target aws|gcp|azure) with the cloud_account asset (prowler + scoutsuite),
// then score per-CIS-section recall against a mock account seeded with a
// known-failing posture. Scoped, short-lived credentials are read from the
// environment by the scan CLI and forwarded into the sandbox — never on disk.
func cloudCmd(argv []string) error {
	fs := flag.NewFlagSet("cloud", flag.ContinueOnError)
	target := fs.String("target", "aws", "cloud provider: aws | gcp | azure")
	groundTruth := fs.String("ground-truth", "", "path to expected-controls.csv (CIS ground truth)")
	binary := fs.String("binary", "./bin/tsengine", "tsengine binary path")
	image := fs.String("image", "tsengine/sandbox:0.1.0", "sandbox image")
	timeout := fs.String("timeout", "30m", "scan timeout (a full account sweep is large)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *groundTruth == "" {
		return fmt.Errorf("--ground-truth is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, time.Hour)
	defer cancelT()

	rep, err := bench.RunCloud(ctx, *target, *groundTruth,
		bench.RunOptions{Binary: *binary, Image: *image, Timeout: *timeout})
	if err != nil {
		return err
	}
	fmt.Print(bench.RenderCloud(rep))
	return nil
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
