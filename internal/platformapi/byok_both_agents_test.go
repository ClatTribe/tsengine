package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A customer configures ONE LLM key through the real settings handler, and it must
// drive BOTH products: the AI Security Engineer (cloud/compliance/triage lanes,
// RoleAnalysis) AND the AI Pentester (exploit/discovery lanes, RoleCode). This is the
// end-to-end proof of the §18.5 "bring your own brain" claim across both agents.
//
// The Deps here has NO operator model (AgentLLM nil, LeadClient unset), so a non-nil
// resolution can ONLY have come from the customer's own configured key — which is what
// makes the assertions mean what they say.
func TestCustomerKey_DrivesBothEngineerAndPentester(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1", Name: "Acme", Plan: platform.PlanFree}); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st, Vault: vault} // deliberately no AgentLLM / LeadClient

	// --- The customer configures their key through the real HTTP handler ---
	// A self-hosted OpenAI-compatible endpoint: buildable without network, and the path
	// most customers with a private model use. (A cloud provider key works identically;
	// this just avoids needing a real vendor key in a unit test.)
	const apiKey = "sk-customer-owned-key-abc123"
	body := `{"provider":"openai-compat","model":"my-model","base_url":"http://llm.acme.internal/v1","api_key":"` + apiKey + `"}`
	rec := httptest.NewRecorder()
	d.handlePutLLMSettings(rec, httptest.NewRequest(http.MethodPut, "/v1/settings/llm", strings.NewReader(body)), "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("customer PUT of an LLM key failed: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), apiKey) {
		t.Fatal("the settings response leaked the customer's API key")
	}

	// The stored key must be SEALED, never plaintext (§18.2 inv. 6).
	tn, _ := st.GetTenant(ctx, "ten-1")
	if tn.LLM == nil || tn.LLM.KeyRef == "" || strings.Contains(tn.LLM.KeyRef, apiKey) {
		t.Fatalf("customer key was not sealed in the store: %+v", tn.LLM)
	}

	// --- The AI Security Engineer lane resolves the customer's key ---
	// RoleAnalysis is what cloudinvestigate / compliance_advisor / apiauthz use.
	engineer := d.resolveAgentLLMForRole(ctx, "ten-1", platform.RoleAnalysis)
	if engineer == nil {
		t.Error("the AI Security Engineer lane did NOT get the customer's configured model")
	}

	// --- The AI Pentester lane resolves the SAME customer's key ---
	// RoleCode is what pentest (ModeDeep) / pentest_discover use.
	pentester := d.resolveAgentLLMForRole(ctx, "ten-1", platform.RoleCode)
	if pentester == nil {
		t.Error("the AI Pentester lane did NOT get the customer's configured model")
	}

	// And the default (role-less) resolution — the general agent path — too.
	if d.resolveAgentLLM(ctx, "ten-1") == nil {
		t.Error("the default agent lane did NOT get the customer's configured model")
	}

	// --- Readiness must AGREE it came from the customer, not the operator ---
	// (There is no operator model here, so any other source would be a false claim.)
	ai := d.aiReadiness(ctx, "ten-1", true)
	if !ai.Configured || ai.Source != "tenant_key" {
		t.Errorf("readiness = {Configured:%v Source:%q}, want Configured:true Source:tenant_key", ai.Configured, ai.Source)
	}
}

// The negative half: with NO operator model and NO customer key, BOTH agent lanes get
// nothing — so the test above can't pass by accident (e.g. a stray operator fallback).
func TestNoKey_NeitherAgentRuns(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "ten-1", Name: "Acme", Plan: platform.PlanFree})
	d := Deps{Store: st} // no vault needed: nothing to seal

	if d.resolveAgentLLMForRole(ctx, "ten-1", platform.RoleAnalysis) != nil {
		t.Error("engineer lane returned a model with no key configured and no operator model")
	}
	if d.resolveAgentLLMForRole(ctx, "ten-1", platform.RoleCode) != nil {
		t.Error("pentester lane returned a model with no key configured and no operator model")
	}
}
