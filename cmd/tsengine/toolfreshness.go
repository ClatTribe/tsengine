package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/toolfresh"
)

// runToolFreshness reports which scanners are version-pinned and how each signature corpus is
// refreshed — the answer to "what version tested this customer", which the product could not
// previously give.
//
// It exists as a COMMAND rather than a package because an inspection nobody can run is the defect
// this repository keeps finding: internal/reachability sat CLI-only for months, and the freshness
// story would have been worse — a package that reports on the build, reachable only from its own
// test, describing a mechanism nobody could invoke.
//
// Offline and deterministic: it reads the build definition, not the network. It never claims a tool
// is out of date, only that the build does not pin it — which is the part that is knowable here and
// the part an operator can fix.
func runToolFreshness(args []string) error {
	fs := flag.NewFlagSet("tool-freshness", flag.ExitOnError)
	path := fs.String("dockerfile", "docker/sandbox/Dockerfile", "path to the sandbox build definition")
	failOnFloating := fs.Bool("fail-on-floating", false,
		"exit non-zero if any scanner floats on latest/master — for CI, where an irreproducible image should block")
	if err := fs.Parse(args); err != nil {
		return err
	}

	b, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read %s: %w", *path, err)
	}
	rep := toolfresh.Parse(string(b))
	if len(rep.Tools) == 0 {
		// A report over nothing must not print a clean bill of health (§10 / §14.2 rule 6).
		return fmt.Errorf("no tool installs recognised in %s — the parser is not seeing its subject, "+
			"so this report would describe an image nobody inspected", *path)
	}
	fmt.Print(rep.Render())

	if *failOnFloating && rep.Floating > 0 {
		return fmt.Errorf("%d scanner(s) float on an unpinned ref — the image is not reproducible, and "+
			"no report can say which version tested the customer", rep.Floating)
	}
	return nil
}
