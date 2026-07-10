package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
)

// integrationCmd runs the credential-free INTEGRATION-COVERAGE benchmark: every
// snapshot-driven integration the AI Security Engineer ingests from, exercised through the
// SAME detector the product runs, against a planted-issues + hardened-decoys estate. No
// mocks, no LLM, no external credential — so anyone can run it on a laptop/CI and get the
// per-integration recall + FP-control number. Exits non-zero unless every integration
// clean-sweeps (a CI gate).
func integrationCmd(argv []string) error {
	fs := flag.NewFlagSet("integration", flag.ContinueOnError)
	out := fs.String("out", "", "write the Markdown scoreboard to this file (default: stdout)")
	jsonOut := fs.Bool("json", false, "emit the per-integration results as JSON instead of Markdown")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	results := bench.RunIntegrationCoverage()
	summary := bench.SummarizeIntegrationCoverage(results)

	if *jsonOut {
		b, _ := json.MarshalIndent(map[string]any{"summary": summary, "integrations": results}, "", "  ")
		fmt.Println(string(b))
	} else {
		md := bench.RenderIntegrationCoverageMarkdown(results)
		if *out != "" {
			if err := os.WriteFile(*out, []byte(md), 0o644); err != nil { //nolint:gosec // operator-controlled path
				return fmt.Errorf("write scoreboard: %w", err)
			}
			fmt.Printf("wrote %s\n", *out)
		} else {
			fmt.Print(md)
		}
	}

	// The gate: every integration must catch every planted issue and flag no decoy.
	if summary.Passed != summary.Integrations || !summary.FPControlClean {
		return fmt.Errorf("integration coverage FAILED: %d/%d integrations clean, %d false positives",
			summary.Passed, summary.Integrations, summary.FalsePositives)
	}
	return nil
}
