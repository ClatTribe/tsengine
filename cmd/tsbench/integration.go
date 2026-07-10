package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ClatTribe/tsengine/internal/bench"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
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
	agent := fs.Bool("agent", false, "ALSO run the LLM agent layer (cloud+code investigate) — needs a model via LLMFromEnv (the dev proxy or a local Ollama)")
	agentOnly := fs.String("agent-only", "", "restrict the agent layer to \"cloud\" or \"code\" (default: both) — for a tractable single-agent proxy run")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	results := bench.RunIntegrationCoverage()
	summary := bench.SummarizeIntegrationCoverage(results)

	// The LLM agent layer is opt-in (it needs a brain). LLMFromEnv resolves the dev proxy
	// (frontier Claude) or a local Ollama — credential-free either way. Absent → honest skip.
	var agentResults []bench.AgentResult
	agentRan := false
	if *agent {
		if llm, ok := cloudengine.LLMFromEnv(); ok {
			agentResults = bench.RunAgentCoverageOnly(context.Background(), llm, *agentOnly)
			agentRan = true
		}
	}

	if *jsonOut {
		payload := map[string]any{"summary": summary, "integrations": results}
		if agentRan {
			payload["agents"] = agentResults
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(b))
	} else {
		md := bench.RenderIntegrationCoverageMarkdown(results)
		if agentRan {
			md += bench.RenderAgentCoverageMarkdown(agentResults)
		} else if *agent {
			md += "\n## AI agent layer\n\n_SKIPPED — no LLM configured. Set `LLM_BASE_URL` to the dev proxy (frontier Claude) or a local Ollama (`http://localhost:11434/v1`), plus `LLM_MODEL` + `LLM_API_KEY`, then re-run with `--agent`._\n"
		}
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
