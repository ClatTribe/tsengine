package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/agentmemory"
	"github.com/ClatTribe/tsengine/internal/cloudsnap"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// firstPrompt records the first prompt a specialist is given, then finishes the run.
type firstPrompt struct{ got string }

func (f *firstPrompt) Generate(_ context.Context, prompt string) (string, error) {
	if f.got == "" {
		f.got = prompt
	}
	return `{"tool":"finish","args":{"summary":"done"}}`, nil
}

const memNote = "payments-api deploys only on Tuesdays"

func memTenant(t *testing.T) *store.Memory {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanEnterprise,
		AgentNotes: []platform.AgentNote{{ID: "n1", Text: memNote}}})
	return st
}

// carriesMemory asserts both the note AND the framing that forbids using it as evidence. The note without
// the framing would be worse than no memory: a customer's remark presented to the agent as a fact.
func carriesMemory(t *testing.T, where, prompt string) {
	t.Helper()
	if !strings.Contains(prompt, memNote) {
		t.Errorf("%s: the specialist's prompt does not carry the customer's memory:\n%.500s", where, prompt)
	}
	if !strings.Contains(prompt, agentmemory.PromptFraming) {
		t.Errorf("%s: memory reached the specialist without the context-not-evidence framing", where)
	}
}

// Every specialist entry point, not the builder: the Lead was wired and the specialists it delegates to
// were not, so a customer's rejected fix was respected by one agent and re-proposed by the next.
func TestSpecialists_CarryTheCustomersMemory(t *testing.T) {
	ctx := context.Background()

	t.Run("cloud on demand", func(t *testing.T) {
		fp := &firstPrompt{}
		h := NewHandler(Deps{Store: memTenant(t), Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: fp})
		if rec := do(h, "POST", "/v1/cloud/investigate", "t1", `{"inventory":{"account_id":"1","provider":"aws"}}`); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		carriesMemory(t, "cloud on demand", fp.got)
	})

	t.Run("cloud delegated by the Lead", func(t *testing.T) {
		fp := &firstPrompt{}
		snaps := cloudsnap.NewMemStore()
		_ = snaps.Put(ctx, cloudsnap.Snapshot{TenantID: "t1", Inventory: []byte(`{"account_id":"1","provider":"aws"}`)})
		d := Deps{Store: memTenant(t), AgentLLM: fp, CloudSnapshots: snaps}
		if _, err := d.cloudInvestigator("t1")(ctx, ""); err != nil {
			t.Fatal(err)
		}
		carriesMemory(t, "cloud delegated", fp.got)
	})

	t.Run("code on demand", func(t *testing.T) {
		fp := &firstPrompt{}
		h := NewHandler(Deps{Store: memTenant(t), Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: fp})
		body := `{"repo":"acme/api","findings":[{"id":"f1","tool":"semgrep","endpoint":"api/h.go:3"}],"source":{"api/h.go":"a\nb\nc"}}`
		if rec := do(h, "POST", "/v1/code/investigate", "t1", body); rec.Code != 200 {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		carriesMemory(t, "code on demand", fp.got)
	})

	t.Run("code delegated by the Lead", func(t *testing.T) {
		fp := &firstPrompt{}
		st := memTenant(t)
		vault, _ := secret.NewAESGCM(make([]byte, 32))
		ref, _ := vault.Seal("ghp_test")
		_ = st.PutConnection(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub, Account: "acme",
			SecretRef: ref, Config: map[string]string{"repo": "api"}, Status: platform.ConnActive})
		_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Tool: "semgrep", RuleID: "semgrep::sqli", Endpoint: "api/h.go:3"})
		d := Deps{Store: st, Vault: vault, AgentLLM: fp}
		inv := d.codeInvestigator("t1")
		if inv == nil {
			t.Fatal("code investigator not built")
		}
		if _, err := inv(ctx, ""); err != nil {
			t.Fatal(err)
		}
		carriesMemory(t, "code delegated", fp.got)
	})
}

// An agent told nothing gets the prompt it always had.
func TestPromptBlock_EmptyRendersNothing(t *testing.T) {
	if agentmemory.PromptBlock(nil) != "" {
		t.Error("an empty memory must add nothing to a prompt")
	}
}
