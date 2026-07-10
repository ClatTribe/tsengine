package bench

import (
	"context"
	"strings"
	"testing"
)

// scriptedCodeLLM plays a fixed codeagent tool sequence (ignoring the prompt): read both
// sources, CONFIRM the real SQLi, REFUSE the parameterized one, finish. It lets the agent
// harness be validated deterministically — no proxy/Ollama needed for CI. `bad` flips it into
// a hallucinator that confirms the SAFE finding too (to prove the grounding check fires).
type scriptedCodeLLM struct {
	n   int
	bad bool
}

func (c *scriptedCodeLLM) Generate(_ context.Context, _ string) (string, error) {
	c.n++
	switch c.n {
	case 1:
		return `{"thought":"read the flagged sink","tool":"read_source","args":{"path":"api/handler.go","line":5}}`, nil
	case 2:
		return `{"thought":"string-concat into a query — real SQLi","tool":"record_issue","args":{"finding_id":"f-sqli","exploitable":true,"severity":"high","rationale":"user input q concatenated into the SQL string","evidence":["api/handler.go:5"],"fix_location":"api/handler.go:5","fix":"use a parameterized query"}}`, nil
	case 3:
		return `{"thought":"read the second sink","tool":"read_source","args":{"path":"api/safe.go","line":5}}`, nil
	case 4:
		if c.bad {
			return `{"thought":"(hallucinating) call it exploitable too","tool":"record_issue","args":{"finding_id":"f-safe","exploitable":true,"severity":"high","rationale":"looks scary","evidence":["api/safe.go:5"],"fix_location":"api/safe.go:5","fix":"x"}}`, nil
		}
		return `{"thought":"parameterized query — NOT exploitable, do not record","tool":"record_issue","args":{"finding_id":"f-safe","exploitable":false,"rationale":"bound parameter, no injection","evidence":["api/safe.go:5"]}}`, nil
	default:
		return `{"thought":"done","tool":"finish","args":{"summary":"1 real SQLi confirmed, 1 safe finding refused"}}`, nil
	}
}

// TestAgentCoverage_CodeAgentGroundedWithScriptedLLM proves the harness scores a well-behaved
// code agent as a clean pass (confirms the real SQLi, invents nothing) — deterministically.
func TestAgentCoverage_CodeAgentGroundedWithScriptedLLM(t *testing.T) {
	r := benchCodeAgent(context.Background(), &scriptedCodeLLM{})
	t.Logf("code agent: recall=%.0f%% confirmed=%d/%d invented=%v", r.Recall()*100, r.Confirmed, r.Planted, r.Invented)
	if !r.Pass() {
		t.Errorf("a grounded code agent must clean-sweep: missed=%v invented=%v", r.Missed, r.Invented)
	}
	if r.Confirmed != 1 {
		t.Errorf("the real SQLi must be confirmed exactly once, got %d", r.Confirmed)
	}
}

// TestAgentCoverage_GroundingCatchesHallucination proves the invented-issue check FIRES when
// the agent wrongly confirms the parameterized (safe) finding — the anti-hallucination gate.
func TestAgentCoverage_GroundingCatchesHallucination(t *testing.T) {
	r := benchCodeAgent(context.Background(), &scriptedCodeLLM{bad: true})
	if len(r.Invented) == 0 {
		t.Fatal("confirming the parameterized safe finding must register as an invented/false confirmation")
	}
	if r.Pass() {
		t.Error("a hallucinating agent must NOT pass")
	}
	if !strings.Contains(strings.Join(r.Invented, " "), "f-safe") {
		t.Errorf("the invented issue should name f-safe, got %v", r.Invented)
	}
}
