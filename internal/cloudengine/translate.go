package cloudengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// EnrichWithLLM is the L2 *translator* pass (CLAUDE.md §2.2): it hands the
// deterministic attack-path findings to an LLM and asks for developer-facing
// prose — a polished per-path narrative + remediation and an overall executive
// risk summary. It rides ON TOP of the deterministic recall floor: the LLM only
// rewrites/summarizes what the engine already found; it never adds or removes a
// path. Graceful — any error leaves the deterministic output untouched.
//
// PRIVACY (ADR 0002): the prompt contains only METADATA the engine already has
// (resource ids, edge kinds, impact, the templated narrative). No data
// contents, no secrets, no credentials are ever sent to the model.
func EnrichWithLLM(ctx context.Context, llm LLM, a *types.AIAssessment) error {
	if llm == nil || a == nil || len(a.Paths) == 0 {
		return nil
	}
	prompt := buildTranslatePrompt(a)
	out, err := llm.Generate(ctx, prompt)
	if err != nil {
		return err // caller decides whether to log; deterministic output already stands
	}
	var parsed struct {
		ExecutiveSummary string `json:"executive_summary"`
		Paths            []struct {
			ID          string `json:"id"`
			Narrative   string `json:"narrative"`
			Remediation string `json:"remediation"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return fmt.Errorf("llm translate: parse response: %w", err)
	}
	if parsed.ExecutiveSummary != "" {
		a.ExecutiveSummary = parsed.ExecutiveSummary
	}
	byID := map[string]int{}
	for i, p := range a.Paths {
		byID[p.ID] = i
	}
	for _, p := range parsed.Paths {
		if i, ok := byID[p.ID]; ok {
			if p.Narrative != "" {
				a.Paths[i].Narrative = p.Narrative
			}
			if p.Remediation != "" {
				a.Paths[i].Remediation = p.Remediation
			}
		}
	}
	return nil
}

func buildTranslatePrompt(a *types.AIAssessment) string {
	var b strings.Builder
	b.WriteString("You are a senior cloud security engineer writing for a developer audience. ")
	b.WriteString("Below are validated cloud attack paths found by a deterministic analyzer. ")
	b.WriteString("Do NOT invent new paths or change the facts — only rewrite for clarity and add a risk summary.\n")
	b.WriteString("Return ONLY JSON of the form: ")
	b.WriteString(`{"executive_summary":"...","paths":[{"id":"...","narrative":"...","remediation":"..."}]}`)
	b.WriteString("\n\nFindings:\n")
	for _, p := range a.Paths {
		fmt.Fprintf(&b, "- id=%s impact=%.2f reachable=%t\n  chain: %s\n  current_fix: %s\n",
			p.ID, p.RealImpact.Score, p.RealImpact.LiveReachable, p.Narrative, p.Remediation)
	}
	return b.String()
}
