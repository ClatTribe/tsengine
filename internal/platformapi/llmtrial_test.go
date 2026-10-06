package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/pentest"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/internal/tenanteval"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// answerer always gives the same verdict — enough to make a candidate agree with every case or none.
type answerer string

func (a answerer) Generate(context.Context, string) (string, error) { return string(a), nil }

// trialDeps builds a tenant with `n` graded cases, each one an issue the customer marked a false
// positive through the real ignore endpoint, so every case expects SUPPRESS.
func trialDeps(t *testing.T, n int, model answerer) (Deps, *store.Memory) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	h := NewHandler(d)
	for i := 0; i < n; i++ {
		f := types.Finding{ID: "f" + itoa(i), RuleID: "deviceposture::disk-unencrypted", Endpoint: "device:laptop-" + itoa(i),
			Severity: types.SeverityHigh, Title: "Disk not encrypted"}
		_ = st.PutFinding(ctx, "t1", f)
		if rec := do(h, "POST", "/v1/issues/ignore", "t1", `{"key":"`+crossdetect.DedupKey(f)+`","reason":"false_positive","by":"sec@acme.com"}`); rec.Code != 200 {
			t.Fatalf("seed ignore: %d %s", rec.Code, rec.Body.String())
		}
	}
	restore := trialClientFor
	trialClientFor = func(string, string, string, string) (pentest.SpecLLM, bool) { return model, true }
	t.Cleanup(func() { trialClientFor = restore })
	return d, st
}

// seedIncumbent records the assigned model's score on the tenant's current suite.
func seedIncumbent(t *testing.T, d Deps, st *store.Memory, passed int) {
	t.Helper()
	cases, _ := d.evalCases(context.Background(), "t1")
	ts := time.Now().UTC().Add(-time.Hour)
	_ = st.PutEvalRun(context.Background(), platform.EvalRun{ID: ts.Format(time.RFC3339Nano), TenantID: "t1", RanAt: ts,
		Cases: len(cases), Passed: passed, SuiteHash: tenanteval.SuiteHash(cases), Arm: tenanteval.ArmModel, Model: "openai/frontier"})
}

type trialResp struct {
	Ran      bool                     `json:"ran"`
	Passed   int                      `json:"passed"`
	Cases    int                      `json:"cases"`
	Evidence tenanteval.RouteEvidence `json:"evidence"`
}

// A trial grades the candidate on the same cases, records it under its own arm, and never stores the
// key or changes the assigned model.
func TestLLMTrial_GradesTheCandidateWithoutAssigningIt(t *testing.T) {
	d, st := trialDeps(t, 12, "SUPPRESS")
	seedIncumbent(t, d, st, 9)
	h := NewHandler(d)
	rec := do(h, "POST", "/v1/settings/llm/trial", "t1", `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1","api_key":"sk-trial-secret"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-trial-secret") {
		t.Fatal("the trial key was echoed")
	}
	var out trialResp
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.Ran || out.Cases < tenanteval.MinRouteCases || out.Passed != out.Cases || out.Evidence.Status != tenanteval.RouteMatches {
		t.Fatalf("trial: %+v", out)
	}
	tn, _ := st.GetTenant(context.Background(), "t1")
	if tn.LLM != nil || len(tn.LLMRoles) != 0 {
		t.Fatalf("a trial must not assign the model or store its key: %+v %+v", tn.LLM, tn.LLMRoles)
	}
	runs, _ := st.ListEvalRuns(context.Background(), "t1")
	found := false
	for _, r := range runs {
		if r.Arm == tenanteval.ArmCandidate && r.Model == "ollama/qwen" {
			found = true
		}
	}
	if !found {
		t.Fatal("the trial was not recorded under the candidate arm")
	}
}

// THE GATE: switching the analysis lane to a model that did worse on the customer's own cases is
// refused with the numbers, and goes through only when acknowledged.
func TestLLMSettings_WorseOnYourOwnCasesNeedsAcknowledging(t *testing.T) {
	d, st := trialDeps(t, 12, "KEEP") // the candidate disagrees with every case
	seedIncumbent(t, d, st, 11)
	h := NewHandler(d)
	if rec := do(h, "POST", "/v1/settings/llm/trial", "t1", `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1"}`); rec.Code != 200 {
		t.Fatalf("trial: %d %s", rec.Code, rec.Body.String())
	}
	put := `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1","role":"analysis"}`
	rec := do(h, "PUT", "/v1/settings/llm", "t1", put)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"worse"`) {
		t.Fatalf("a worse model must be refused with the evidence: %d %s", rec.Code, rec.Body.String())
	}
	if tn, _ := st.GetTenant(context.Background(), "t1"); tn.LLMRoles[platform.RoleAnalysis] != nil {
		t.Fatal("a refused switch was saved")
	}
	ack := strings.Replace(put, `"role":"analysis"`, `"role":"analysis","acknowledge_lower_score":true`, 1)
	if rec := do(h, "PUT", "/v1/settings/llm", "t1", ack); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"worse"`) {
		t.Fatalf("an acknowledged switch must go through and still carry the evidence: %d %s", rec.Code, rec.Body.String())
	}
	// The DEFAULT model drives analysis when no override exists, so it is gated the same way.
	def := `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1"}`
	if rec := do(h, "PUT", "/v1/settings/llm", "t1", def); rec.Code != 409 {
		t.Fatalf("the default slot drives analysis and must be gated too: %d", rec.Code)
	}
}

// The code lanes are checked per fix by executing tests (the cascade), not by this gate; and a switch
// with no trial at all is allowed but labelled unmeasured, never read as safe.
func TestLLMSettings_GateScope(t *testing.T) {
	d, st := trialDeps(t, 12, "KEEP")
	seedIncumbent(t, d, st, 11)
	h := NewHandler(d)
	_ = do(h, "POST", "/v1/settings/llm/trial", "t1", `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1"}`)
	if rec := do(h, "PUT", "/v1/settings/llm", "t1", `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1","role":"code"}`); rec.Code != 200 {
		t.Fatalf("the code lane is not gated by eval agreement: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(h, "PUT", "/v1/settings/llm", "t1", `{"provider":"ollama","model":"untried","base_url":"http://localhost:11434/v1","role":"analysis"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"unmeasured"`) {
		t.Fatalf("an untried model is allowed but must be labelled unmeasured: %d %s", rec.Code, rec.Body.String())
	}
}

// The customer's instructions still apply: deterministic-only means no model is asked anything.
func TestLLMTrial_RespectsDeterministicOnly(t *testing.T) {
	d, st := trialDeps(t, 12, "SUPPRESS")
	tn, _ := st.GetTenant(context.Background(), "t1")
	tn.AIMode = platform.AIModeDeterministic
	_ = st.PutTenant(context.Background(), tn)
	if rec := do(NewHandler(d), "POST", "/v1/settings/llm/trial", "t1", `{"provider":"ollama","model":"qwen","base_url":"http://localhost:11434/v1"}`); rec.Code != 409 {
		t.Fatalf("a deterministic-only workspace must refuse a trial: %d", rec.Code)
	}
}
