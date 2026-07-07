package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// scriptedCodeLLM drives the code agent loop through a fixed tool sequence (ignores the prompt).
type scriptedCodeLLM struct {
	replies []string
	i       int
}

func (s *scriptedCodeLLM) Generate(_ context.Context, _ string) (string, error) {
	if s.i >= len(s.replies) {
		return `{"tool":"finish","args":{"summary":"done"}}`, nil
	}
	r := s.replies[s.i]
	s.i++
	return r, nil
}

func TestCodeInvestigate_GatedWithoutLLM(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}) // no AgentLLM
	rec := do(h, "POST", "/v1/code/investigate", "t1",
		`{"repo":"acme/api","findings":[{"id":"f1","tool":"semgrep","endpoint":"api/h.go:3"}],"source":{"api/h.go":"a\nb\nc"}}`)
	if rec.Code != 400 {
		t.Fatalf("without an LLM the run must be gated (400), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCodeInvestigate_RunsAndGroundsAssessment(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise}) // AI is a paid feature
	llm := &scriptedCodeLLM{replies: []string{
		`{"tool":"list_findings","args":{}}`,
		`{"tool":"read_source","args":{"path":"api/handler.go","line":3}}`,
		`{"tool":"record_issue","args":{"finding_id":"f1","exploitable":true,"severity":"high","rationale":"tainted q reaches the query","evidence":["api/handler.go:3"],"fix_location":"api/handler.go:3","fix":"parameterize"}}`,
		`{"tool":"finish","args":{"summary":"1 exploitable SQLi confirmed at source"}}`,
	}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: llm})

	body := `{"repo":"acme/api","findings":[{"id":"f1","tool":"semgrep","severity":"high","endpoint":"api/handler.go:3","title":"SQLi"}],` +
		`"source":{"api/handler.go":"package api\nfunc Search(r *http.Request){\n q := r.URL.Query().Get(\"q\"); db.Query(\"...\"+q)\n}"}}`
	rec := do(h, "POST", "/v1/code/investigate", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("run should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Summary string `json:"summary"`
		Issues  []struct {
			FindingID   string `json:"finding_id"`
			Exploitable bool   `json:"exploitable"`
			FixLocation string `json:"fix_location"`
		} `json:"issues"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Issues) != 1 || out.Issues[0].FindingID != "f1" || !out.Issues[0].Exploitable || out.Issues[0].FixLocation == "" {
		t.Fatalf("expected one grounded exploitable issue, got %s", rec.Body.String())
	}
	if out.Summary == "" {
		t.Error("summary should be set")
	}
}
