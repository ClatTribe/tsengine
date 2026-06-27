package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func cloudagentIssueFixture() cloudagent.Issue {
	return cloudagent.Issue{
		ID: "i-1", Target: "arn:aws:s3:::secrets", TargetName: "secrets bucket",
		Path: []string{"internet", "ec2", "role", "s3"}, Severity: "critical",
		Rationale: "public EC2 → role → readable secrets bucket", Evidence: []string{"find_paths ok"},
		Remediation: "remove s3:GetObject from the role", FixKind: "iam_policy", FixVerified: true,
	}
}

// fakeCloudLLM drives the cloud agent loop in tests; the default reply finishes immediately.
type fakeCloudLLM struct{}

func (fakeCloudLLM) Generate(_ context.Context, _ string) (string, error) {
	return `{"thought":"nothing reachable","tool":"finish","args":{"summary":"no real attack paths"}}`, nil
}

func TestCloudInvestigate_GatedWithoutLLM(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}) // no AgentLLM
	rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"1","provider":"aws"}}`)
	if rec.Code != 400 {
		t.Fatalf("without an LLM the run must be gated (400), got %d: %s", rec.Code, rec.Body.String())
	}
	// the view still works and reports it's not runnable.
	v := do(h, "GET", "/v1/cloud/investigate", "t1", "")
	var view struct {
		Total   int  `json:"total"`
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(v.Body.Bytes(), &view)
	if view.Enabled {
		t.Error("enabled should be false when no AgentLLM is wired")
	}
}

func TestCloudInvestigate_RunsAndViewReturnsPaths(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanGrowth}) // AI is a paid feature
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: fakeCloudLLM{}})

	// Run over a minimal inventory — the agent finishes with 0 proven paths (happy path, 200).
	rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"123456789012","provider":"aws"}}`)
	if rec.Code != 200 {
		t.Fatalf("run should be 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Seed a stored cloud-agent attack-path finding (as a real investigation would) and confirm the view surfaces it.
	_ = st.PutFinding(context.Background(), "t1", cloudIssueToFinding("ca-1", cloudagentIssueFixture()))
	v := do(h, "GET", "/v1/cloud/investigate", "t1", "")
	var view struct {
		Total   int             `json:"total"`
		Enabled bool            `json:"enabled"`
		Paths   []types.Finding `json:"paths"`
	}
	_ = json.Unmarshal(v.Body.Bytes(), &view)
	if view.Total != 1 || !view.Enabled {
		t.Fatalf("view should show 1 path + enabled, got total=%d enabled=%v", view.Total, view.Enabled)
	}
	if view.Paths[0].Tool != "cloudagent" || view.Paths[0].VerificationStatus != types.VerificationVerified {
		t.Errorf("stored path should be tool=cloudagent + verified, got %+v", view.Paths[0])
	}

	// Tenant isolation: t2 sees none of t1's paths.
	v2 := do(h, "GET", "/v1/cloud/investigate", "t2", "")
	var view2 struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(v2.Body.Bytes(), &view2)
	if view2.Total != 0 {
		t.Errorf("tenant isolation breached: t2 sees %d of t1's paths", view2.Total)
	}
}

func TestCloudIssueToFinding_Maps(t *testing.T) {
	f := cloudIssueToFinding("ca-9", cloudagentIssueFixture())
	if f.RuleID != "cloudagent::attack-path" || f.Tool != "cloudagent" || f.Endpoint != "arn:aws:s3:::secrets" {
		t.Errorf("mapping wrong: %+v", f)
	}
	if f.Severity != types.SeverityCritical {
		t.Errorf("severity should map from the issue, got %q", f.Severity)
	}
	var raw map[string]any
	_ = json.Unmarshal(f.RawOutput, &raw)
	if raw["fix_verified"] != true {
		t.Errorf("raw_output should carry the agent's fix metadata, got %v", raw)
	}
}

func TestSeedRisks_AgentFindingsProposeVCISORisks(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}

	// Two proven cloud-agent attack paths (high+) land as findings...
	_ = st.PutFinding(context.Background(), "t1", cloudIssueToFinding("ca-1", cloudagentIssueFixture()))
	_ = st.PutFinding(context.Background(), "t1", cloudIssueToFinding("ca-2", cloudagentIssueFixture()))

	// ...seedRisks clusters them into a candidate Risk for the named vCISO to judge.
	seeded, err := d.seedRisks(context.Background(), "t1")
	if err != nil {
		t.Fatalf("seedRisks: %v", err)
	}
	if len(seeded) == 0 {
		t.Fatal("agent attack-path findings should propose at least one candidate risk for the vCISO")
	}
	for _, rk := range seeded {
		if !rk.Proposed || rk.DecidedBy != "" {
			t.Errorf("a seeded risk must be a PROPOSAL awaiting a human decision, got %+v", rk)
		}
	}
}

func TestResolveAgentLLM_FallsBackToOperatorGlobal(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: fakeCloudLLM{}}
	// An AI-enabled (paid) tenant with no own key falls back to the operator-global d.AgentLLM.
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "paid", Plan: platform.PlanGrowth})
	if got := d.resolveAgentLLM(context.Background(), "paid"); got == nil {
		t.Error("paid tenant with no own LLM should fall back to the operator-global AgentLLM")
	}
	// The economic gate: a Free (or unknown) tenant must NOT spend the operator's LLM budget.
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "free", Plan: platform.PlanFree})
	if got := d.resolveAgentLLM(context.Background(), "free"); got != nil {
		t.Error("Free tenant must NOT get the operator-global LLM (no operator spend on free)")
	}
	if got := d.resolveAgentLLM(context.Background(), "ghost"); got != nil {
		t.Error("unknown tenant must default to no operator LLM (fail-safe)")
	}
}
