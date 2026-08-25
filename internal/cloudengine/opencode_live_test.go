package cloudengine

import (
	"context"
	"os"
	"testing"
)

// Live probe against a locally-running `opencode serve` — skipped unless
// TSENGINE_LLM_OPENCODE points at one. Not part of CI: it drives a real model.
func TestOpenCodeLive(t *testing.T) {
	if os.Getenv("TSENGINE_LLM_OPENCODE") == "" {
		t.Skip("no TSENGINE_LLM_OPENCODE set")
	}
	llm, ok := OpenCodeFromEnv()
	if !ok {
		t.Fatal("env set but adapter not built")
	}
	out, err := llm.Generate(context.Background(), `Reply with exactly this JSON and nothing else: {"verdict":"clean","rationale":"live"}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Logf("model=%s out=%.120s", llm.ModelName(), out)
}
