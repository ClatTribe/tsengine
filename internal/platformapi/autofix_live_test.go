package platformapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestAutofix_Live drives the AI autofix agent against a real model (local Ollama by default) over a
// concrete SAST finding, asserting it produces a non-empty grounded patch. Skipped without LLM_BASE_URL.
func TestAutofix_Live(t *testing.T) {
	base := os.Getenv("LLM_BASE_URL")
	if base == "" {
		t.Skip("set LLM_BASE_URL to run the live autofix test")
	}
	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}
	llm := cloudengine.NewOpenAICompat(os.Getenv("LLM_API_KEY"), model, base)
	f := types.Finding{
		ID: "f-1", RuleID: "semgrep::sql-injection", Tool: "semgrep", Severity: types.SeverityHigh,
		CWE: []string{"CWE-89"}, Endpoint: "internal/db/users.go:42", Title: "SQL injection via string concat",
		Description: `user id concatenated into a query: db.Query("SELECT * FROM users WHERE id = '" + id + "'")`,
	}
	out, err := llm.Generate(context.Background(), buildAutofixPrompt(f))
	if err != nil {
		t.Fatalf("%s autofix errored: %v", model, err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("%s produced an empty autofix", model)
	}
	t.Logf("PASS: %s produced a %d-char autofix (snippet: %.120q)", model, len(out), out)
}
