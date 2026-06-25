package l2

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestLeadAgent_Live drives the L2 Lead/translator agent against a REAL model (a local Ollama by
// default) over a couple of L1 findings, asserting the loop completes and reports its outcome. Skipped
// unless LLM_BASE_URL is set, so CI stays green with no model. Part-4 "test the agent with a local
// thinking model" harness:
//
//	LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b LLM_API_KEY=ollama \
//	  go test ./internal/l2 -run TestLeadAgent_Live -v -timeout 10m
func TestLeadAgent_Live(t *testing.T) {
	base := os.Getenv("LLM_BASE_URL")
	if base == "" {
		t.Skip("set LLM_BASE_URL (e.g. http://localhost:11434/v1) to run the live Lead-agent test")
	}
	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}
	client := NewOpenAICompatClient(model, base, os.Getenv("LLM_API_KEY"))

	target := types.Asset{Type: types.AssetWebApplication, Target: "https://demo.test"}
	l1 := []types.Finding{
		{ID: "f-001", RuleID: "nuclei::sqli-error-based", Tool: "nuclei", Severity: types.SeverityHigh,
			CWE: []string{"CWE-89"}, Endpoint: "https://demo.test/search?q=", Title: "Error-based SQL injection in q",
			Description: "The q parameter is concatenated into a SQL query; an error-based payload returns a DB error."},
		{ID: "f-002", RuleID: "nuclei::missing-hsts", Tool: "nuclei", Severity: types.SeverityLow,
			Endpoint: "https://demo.test/", Title: "Missing HSTS header"},
	}
	d := Deps{Target: target, L1Findings: l1}
	// A local thinking model is SLOW — bound the loop tightly so the test proves the model drives the
	// loop (calls tools, advances phases) without waiting on a full 60-iteration investigation.
	budget := DefaultBudget()
	budget.MaxIterations = 4
	budget.MaxIdleTurns = 2
	budget.MaxWallClock = 8 * time.Minute
	a, err := New(client, BuildCatalog(d), budget)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := a.Run(context.Background(), target, l1)
	if err != nil {
		t.Fatalf("%s drove the Lead loop to an error: %v", model, err)
	}
	t.Logf("PASS: %s drove the Lead — stop=%s phase=%s reports=%d iters=%d", model, out.StopReason, out.Phase, len(out.Findings), out.Iterations)
	// The loop must make real progress (call tools, advance phases), not stall on turn 0.
	if out.Iterations == 0 {
		t.Errorf("the Lead made 0 iterations — the model produced no tool calls")
	}
}
