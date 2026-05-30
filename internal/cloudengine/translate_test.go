package cloudengine

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// mockLLM returns a canned response and records the prompt it saw.
type mockLLM struct {
	resp       string
	lastPrompt string
	err        error
}

func (m *mockLLM) Generate(_ context.Context, prompt string) (string, error) {
	m.lastPrompt = prompt
	return m.resp, m.err
}

func TestEnrichWithLLM_MergesAndIsMetadataOnly(t *testing.T) {
	a := &types.AIAssessment{Paths: []types.AttackPath{
		{ID: "acp-001", Narrative: "templated chain", Remediation: "templated fix",
			RealImpact: types.RealImpact{Score: 1, LiveReachable: true}},
	}}
	m := &mockLLM{resp: `{"executive_summary":"One internet-reachable path to PII.",
		"paths":[{"id":"acp-001","narrative":"An attacker on the internet can reach your PII bucket.","remediation":"Scope the data-role trust policy."}]}`}

	if err := EnrichWithLLM(context.Background(), m, a); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if a.ExecutiveSummary == "" {
		t.Error("executive summary should be set from the LLM")
	}
	if a.Paths[0].Narrative != "An attacker on the internet can reach your PII bucket." {
		t.Errorf("narrative not replaced: %q", a.Paths[0].Narrative)
	}
	if a.Paths[0].Remediation != "Scope the data-role trust policy." {
		t.Errorf("remediation not replaced: %q", a.Paths[0].Remediation)
	}
	// privacy: the prompt is metadata only — never the literal phrases a data
	// read would contain. (Sanity: the prompt should not request data contents.)
	if strings.Contains(strings.ToLower(m.lastPrompt), "getobject") {
		t.Error("translate prompt must not reference data-contents reads")
	}
}

func TestEnrichWithLLM_GracefulNoLLM(t *testing.T) {
	a := &types.AIAssessment{Paths: []types.AttackPath{{ID: "x", Narrative: "keep me"}}}
	if err := EnrichWithLLM(context.Background(), nil, a); err != nil {
		t.Fatalf("nil llm must be a no-op, got %v", err)
	}
	if a.Paths[0].Narrative != "keep me" {
		t.Error("deterministic narrative must survive when there is no LLM")
	}
}

func TestEnrichWithLLM_BadJSONLeavesDeterministic(t *testing.T) {
	a := &types.AIAssessment{Paths: []types.AttackPath{{ID: "x", Narrative: "keep me"}}}
	m := &mockLLM{resp: "not json"}
	if err := EnrichWithLLM(context.Background(), m, a); err == nil {
		t.Error("malformed LLM output should return an error")
	}
	if a.Paths[0].Narrative != "keep me" {
		t.Error("deterministic narrative must survive a bad LLM response")
	}
}
