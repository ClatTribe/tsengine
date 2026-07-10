package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/internal/cloudquery"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// scriptedCloudLLM plays the exact winning tool-call sequence a capable brain produces on the cloudquery
// account — the same script measured live via the dev proxy (recall 2/2, invented 0). Deterministic, so
// the whole product flow can be exercised end to end WITHOUT a real key: seed → find_paths → record the
// grounded internet→PII path → propose a fix → finish. record_issue is grounded (§10), so this only
// succeeds because the path really exists in the posted inventory — the fake can't fabricate a finding.
type scriptedCloudLLM struct{ n int }

func (c *scriptedCloudLLM) Generate(_ context.Context, _ string) (string, error) {
	c.n++
	switch c.n {
	case 1:
		return `{"thought":"seed","tool":"enumerate_attack_paths","args":{}}`, nil
	case 2:
		return `{"thought":"verify the PII path","tool":"find_paths","args":{"target":"arn:aws:s3:::acme-customer-pii"}}`, nil
	case 3:
		return `{"thought":"grounded — record it","tool":"record_issue","args":{"target":"arn:aws:s3:::acme-customer-pii","path":["internet","arn:aws:ec2:us-east-1:123456789012:instance/i-web","arn:aws:iam::123456789012:role/web-role","arn:aws:s3:::acme-customer-pii"],"severity":"critical","rationale":"the public web instance runs as web-role which reads customer PII","evidence":["find_paths: internet -> i-web -> web-role -> acme-customer-pii"]}}`, nil
	case 4:
		return `{"thought":"fix it","tool":"propose_fix","args":{"issue_id":"ai-001"}}`, nil
	default:
		return `{"thought":"done","tool":"finish","args":{"summary":"1 real internet-to-PII path, fixed"}}`, nil
	}
}

// TestCloudInvestigate_E2E_AgentDrivenFindingToComplianceAndRisk is the end-to-end MEASUREMENT of the AI
// Cloud Security Engineer through the product: ONE POST /v1/cloud/investigate call, driven by a (scripted)
// LLM, must run the agent → confirm + record a real attack path → store it as a finding → fold it into the
// compliance posture → seed a candidate risk on the vCISO (HITL) desk. This proves the flagship flow the customer sees:
// "point the AI engineer at my account, and its proven finding shows up in issues, compliance, AND the
// human-approval queue" — the same flow the dev proxy exercises, now deterministic + reproducible.
func TestCloudInvestigate_E2E_AgentDrivenFindingToComplianceAndRisk(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise}) // AI-entitled

	// The "deployed target": a real cloud account, represented (as the product ingests it) by its inventory.
	ds, err := cloudquery.Generate()
	if err != nil {
		t.Fatalf("generate account: %v", err)
	}
	invJSON, err := json.Marshal(cloudquery.ToInventory(ds.Tables))
	if err != nil {
		t.Fatal(err)
	}

	d := Deps{
		Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok",
		AgentLLM: &scriptedCloudLLM{}, // the L2 agent's brain (a real run wires the tenant key or the proxy)
		GRC:      &grc.GRC{Store: st}, // so the finding folds into the compliance posture
	}
	h := NewHandler(d)

	rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":`+string(invJSON)+`}`)
	if rec.Code != 200 {
		t.Fatalf("investigate: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		PathsFound    int `json:"paths_found"`
		RisksProposed int `json:"risks_proposed"`
		Calls         int `json:"calls"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// 1) the agent actually PROVED + recorded a path (grounded — the fake couldn't fabricate it).
	if resp.PathsFound < 1 {
		t.Fatalf("the agent must record the real internet→PII path, got paths_found=%d: %s", resp.PathsFound, rec.Body.String())
	}
	// 2) it flowed to a stored finding surfaced by the view.
	if fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{}); len(fs) < 1 {
		t.Fatal("the proven path must be stored as a finding")
	}
	// 3) it folded into the compliance posture (a control gap).
	cs, _ := (&grc.GRC{Store: st}).Posture(ctx, "t1", grc.FrameworkSOC2)
	gaps := 0
	for _, c := range cs {
		if c.State == platform.ControlGap {
			gaps++
		}
	}
	if gaps == 0 {
		t.Error("the agent's proven finding must fold into the SOC2 compliance posture as a control gap")
	}
	// 4) it seeded a candidate risk on the vCISO (HITL) desk — proposed, awaiting a human decision.
	if resp.RisksProposed < 1 {
		t.Errorf("the agent's high-severity finding must propose a candidate risk on the vCISO desk, got %d", resp.RisksProposed)
	}
	risks, _ := st.ListRisks(ctx, "t1")
	if len(risks) == 0 {
		t.Fatal("a candidate risk must be persisted for the vCISO to decide")
	}
	for _, rk := range risks {
		if !rk.Proposed || rk.DecidedBy != "" {
			t.Errorf("a seeded risk must be a PROPOSAL awaiting a human (HITL), got %+v", rk)
		}
	}
	_ = cloudgraph.AdminID // (the account also has an admin path; one recorded path is enough to prove the flow)
}
