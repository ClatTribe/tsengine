package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// sirbenchCmd runs our AI Security Engineer against SIR-Bench (arXiv:2604.12040) — the shared
// public incident-response benchmark — and reports M1/M2/M3 next to the published baseline.
// Built-in representative cases run today; --suite <cases.json> runs the official operator-
// provided suite (the honest gate; the 794 official cases aren't a public download).
func sirbenchCmd(argv []string) error {
	fs := flag.NewFlagSet("sirbench", flag.ContinueOnError)
	suite := fs.String("suite", "", "official SIR-Bench case export (JSON array of cases) — the headline comparison")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	var cases []bench.SIRCase
	official := false
	if *suite != "" {
		c, err := bench.LoadSIRSuite(*suite)
		if err != nil {
			return err
		}
		cases, official = c, true
	}
	r := bench.RunSIRBench(cases, official)
	if *jsonOut {
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(bench.RenderSIRMarkdown(r))
	return nil
}
