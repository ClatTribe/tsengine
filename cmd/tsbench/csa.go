package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// csaCmd runs the CSA "Beyond the Hype" AI-SOC scenarios through our engine's deterministic
// detectors and prints triage accuracy next to the published Dropzone/manual numbers. No LLM key,
// no proxy — the number is autonomous + reproducible (the point).
func csaCmd(argv []string) error {
	fs := flag.NewFlagSet("csa", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the raw scorecard as JSON")
	out := fs.String("out", "", "write the Markdown report to this file (default: stdout)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	results := bench.RunCSABench()
	if *asJSON {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	md := bench.RenderCSAMarkdown(results)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil { //nolint:gosec // report artifact
			return err
		}
		fmt.Printf("wrote %s\n", *out)
		return nil
	}
	fmt.Print(md)
	return nil
}
