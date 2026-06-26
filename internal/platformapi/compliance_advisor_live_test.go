package platformapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/grc"
)

// TestAdvisor_Live drives the compliance advisor agent against a real model (local Ollama by default) over
// a grounded posture (30% coverage, 2 gaps, manual areas), asserting it produces a non-empty roadmap.
// Skipped without LLM_BASE_URL.
func TestAdvisor_Live(t *testing.T) {
	base := os.Getenv("LLM_BASE_URL")
	if base == "" {
		t.Skip("set LLM_BASE_URL to run the live advisor test")
	}
	model := os.Getenv("LLM_MODEL")
	if model == "" {
		model = "qwen3:8b"
	}
	llm := cloudengine.NewOpenAICompat(os.Getenv("LLM_API_KEY"), model, base)
	rep := &grc.Report{
		Title:    "SOC 2",
		Coverage: grc.Coverage{AssessedControls: 3, AssessableControls: 10, AutomatedCoveragePct: 30, Gaps: 2, NotAssessed: 7},
		Rows:     []grc.ReportRow{{ControlID: "CC6.1", Gap: true}, {ControlID: "CC7.2", Gap: true}},
	}
	readiness := grc.ScopeReadiness([]string{"soc2"}, map[string]bool{"identity": true, "cloud": true})
	out, err := llm.Generate(context.Background(), buildAdvisorPrompt(rep, readiness))
	if err != nil {
		t.Fatalf("%s advisor errored: %v", model, err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("%s produced an empty roadmap", model)
	}
	t.Logf("PASS: %s produced a %d-char roadmap (snippet: %.140q)", model, len(out), out)
}
