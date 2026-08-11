package cweattrib

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestLive_AttributionAgainstARealModel exercises the tier against a real LLM, because the fake-LLM
// tests prove the GUARDS work but not that a model can actually do the job through this prompt.
//
// The two cases are the ones that matter and pull in opposite directions:
//
//	a real weakness       → must be classified (the capability)
//	a non-weakness        → must be declined   (the safety property models measurably fail)
//
// Skipped without a configured model, so CI is unaffected. Run with:
//
//	LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b go test ./internal/cweattrib/ -run Live -v
func TestLive_AttributionAgainstARealModel(t *testing.T) {
	llm, ok := cloudengine.LLMFromEnv()
	if !ok {
		t.Skip("no LLM configured — set LLM_BASE_URL + LLM_MODEL for the live attribution check")
	}
	a := Attributor{LLM: llm, Allowed: []string{
		"CWE-22", "CWE-79", "CWE-89", "CWE-306", "CWE-319", "CWE-327", "CWE-502", "CWE-798", "CWE-918",
	}}
	ctx := context.Background()

	t.Run("classifies a real weakness", func(t *testing.T) {
		got := a.Attribute(ctx, types.Finding{
			ID: "f1", Tool: "semgrep", RuleID: "string-formatted-query",
			Title:       "Query assembled by concatenation",
			Description: "A value taken from the HTTP request is concatenated into the statement text before execution, rather than bound as a parameter.",
		})
		fmt.Printf("  weakness  → cwe=%q reason=%q\n", got.CWE, got.Reason)
		// A model we could not REACH tells us nothing about attribution. This matters in practice: a
		// stray LLM_API_KEY in the environment resolves a cloud provider that may be rate-limited, and
		// scoring those 429s as a classification failure would slander whichever model was intended.
		if strings.Contains(got.Reason, "model unavailable") {
			t.Skipf("model unreachable (%s) — transport, not attribution", got.Reason)
		}
		if got.CWE == "" {
			t.Errorf("a textbook injection was not classified (reason: %s)", got.Reason)
		}
	})

	t.Run("declines a non-weakness", func(t *testing.T) {
		got := a.Attribute(ctx, types.Finding{
			ID: "f2", Tool: "syft", RuleID: "license.copyleft-in-proprietary",
			Title:       "Copyleft-licensed dependency in a proprietary distribution",
			Description: "A bundled library is distributed under a reciprocal licence that conflicts with the product's distribution model. The library functions correctly and has no known defect.",
		})
		fmt.Printf("  licence   → cwe=%q reason=%q\n", got.CWE, got.Reason)
		if strings.Contains(got.Reason, "model unavailable") {
			t.Skipf("model unreachable (%s) — transport, not attribution", got.Reason)
		}
		if got.CWE != "" {
			t.Errorf("attributed %q to a licensing conflict — this is the over-attribution that puts "+
				"inapplicable controls into a signed evidence pack", got.CWE)
		}
	})
}
