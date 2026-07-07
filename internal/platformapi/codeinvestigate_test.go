package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
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

// TestCodeInvestigator_GatedOffWithoutConnectedRepo: the L2-delegation closure is nil (so the
// investigate_code tool is NOT exposed → the ≤12-tool cap stays clean) unless the tenant has a GitHub
// connection with a configured repo + a vault. This is the cap-safety guarantee.
func TestCodeInvestigator_GatedOffWithoutConnectedRepo(t *testing.T) {
	ctx := context.Background()
	vault, _ := secret.NewAESGCM(make([]byte, 32))
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	d := Deps{Store: st, Vault: vault}

	// no connection at all → nil.
	if d.codeInvestigator("t1") != nil {
		t.Error("no github connection → codeInvestigator must be nil (tool not exposed)")
	}
	// a github connection with NO configured repo → still nil (can't build a live source).
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme", SecretRef: "ref"})
	if d.codeInvestigator("t1") != nil {
		t.Error("github connection without a configured repo → codeInvestigator must be nil")
	}
	// a github connection WITH a repo → non-nil (the tool activates).
	_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme", SecretRef: "ref", Config: map[string]string{"repo": "api"}})
	if d.codeInvestigator("t1") == nil {
		t.Error("github connection with a configured repo → codeInvestigator should activate")
	}
	// no vault → nil regardless (can't open the token).
	if (Deps{Store: st}).codeInvestigator("t1") != nil {
		t.Error("no vault → codeInvestigator must be nil")
	}
}

// TestCodeIssueToFinding_DistinctRuleIDsAndSeverity: two confirmed issues at the SAME endpoint must map to
// DISTINCT findings (RuleID carries the assessed finding id) so detect.Key can't collapse/mask one; and an
// un-graded confirmation defaults to medium, never a silent High escalation.
func TestCodeIssueToFinding_DistinctRuleIDsAndSeverity(t *testing.T) {
	a := codeIssueToFinding("id-a", "acme/api", codeagent.CodeIssue{FindingID: "f1", FixLocation: "db.go:40", Severity: ""})
	b := codeIssueToFinding("id-b", "acme/api", codeagent.CodeIssue{FindingID: "f2", FixLocation: "db.go:40", Severity: ""})
	if a.RuleID == b.RuleID {
		t.Errorf("two confirmations must have distinct RuleIDs (else detect.Key collides): %q", a.RuleID)
	}
	if detectKeyOf(a) == detectKeyOf(b) {
		t.Errorf("distinct confirmations must not share a detect key: %q", detectKeyOf(a))
	}
	if a.Severity != types.SeverityMedium {
		t.Errorf("un-graded confirmation must default to medium, not High; got %s", a.Severity)
	}
}

// detectKeyOf mirrors detect.Key (rule_id|endpoint) for the collision assertion above.
func detectKeyOf(f types.Finding) string { return f.RuleID + "|" + f.Endpoint }

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
		Summary              string `json:"summary"`
		ConfirmedExploitable int    `json:"confirmed_exploitable"`
		Issues               []struct {
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
	// The confirmed-exploitable assessment must PERSIST as a first-class verified codeagent finding
	// (so it flows through issues / grc / incidents), and tenant-scoped.
	if out.ConfirmedExploitable != 1 {
		t.Errorf("one exploitable assessment should persist, confirmed=%d", out.ConfirmedExploitable)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	var codeF int
	for _, f := range fs {
		if f.Tool == "codeagent" {
			codeF++
			if f.VerificationStatus != types.VerificationVerified {
				t.Errorf("codeagent finding should be verified, got %s", f.VerificationStatus)
			}
		}
	}
	if codeF != 1 {
		t.Errorf("want 1 stored codeagent finding, got %d", codeF)
	}

	// The GET view surfaces the stored assessment (survives navigation) + reports enabled, tenant-scoped.
	v := do(h, "GET", "/v1/code/investigate", "t1", "")
	var view struct {
		Total     int             `json:"total"`
		Enabled   bool            `json:"enabled"`
		Confirmed []types.Finding `json:"confirmed"`
	}
	_ = json.Unmarshal(v.Body.Bytes(), &view)
	if view.Total != 1 || !view.Enabled || len(view.Confirmed) != 1 || view.Confirmed[0].Tool != "codeagent" {
		t.Errorf("GET view should show the 1 stored codeagent assessment + enabled, got %s", v.Body.String())
	}
	// tenant isolation: t2 sees none of t1's assessments.
	v2 := do(h, "GET", "/v1/code/investigate", "t2", "")
	var view2 struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(v2.Body.Bytes(), &view2)
	if view2.Total != 0 {
		t.Errorf("tenant isolation breached: t2 sees %d of t1's assessments", view2.Total)
	}
}
