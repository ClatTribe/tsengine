package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/secret"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestResolveLeadClient_PerTenantProviders: a customer who configures their OWN key must drive the L2 Lead
// (Triage / Investigate) with THAT key, for every offered provider. Before the fix, only OpenAI-compat
// tenant keys were honoured — an Anthropic/Claude key (the default provider in the UI) silently fell through
// to the operator-global client, so a paying customer's Claude key could not run the flagship triage.
func TestResolveLeadClient_PerTenantProviders(t *testing.T) {
	ctx := context.Background()
	vault, err := secret.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		provider, model string
		wantModel       string
		wantType        string // concrete l2.Client type expected
	}{
		{"anthropic", "claude-opus-4-8", "claude-opus-4-8", "*l2.AnthropicClient"},
		{"claude", "claude-sonnet-4-5", "claude-sonnet-4-5", "*l2.AnthropicClient"},
		{"gemini", "gemini-2.0-flash", "gemini-2.0-flash", "*l2.OpenAICompatClient"},
		{"openai", "gpt-4o", "gpt-4o", "*l2.OpenAICompatClient"},
	}
	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			st := store.NewMemory()
			sealed, serr := vault.Seal("tenant-key-123")
			if serr != nil {
				t.Fatal(serr)
			}
			if perr := st.PutTenant(ctx, platform.Tenant{ID: "ten", Name: "Acme",
				LLM: &platform.LLMConfig{Provider: c.provider, Model: c.model, KeyRef: sealed}}); perr != nil {
				t.Fatal(perr)
			}
			// NOTE: no operator-global d.LeadClient — so a non-nil result can ONLY come from the tenant key.
			d := Deps{Store: st, Vault: vault}
			client := d.resolveLeadClient(ctx, "ten")
			if client == nil {
				t.Fatalf("provider %q: tenant key must yield a Lead client (got nil — fell through)", c.provider)
			}
			if got := typeName(client); got != c.wantType {
				t.Errorf("provider %q: client type = %s, want %s", c.provider, got, c.wantType)
			}
			if client.Model() != c.wantModel {
				t.Errorf("provider %q: model = %q, want %q", c.provider, client.Model(), c.wantModel)
			}
		})
	}
}

// typeName returns the concrete pointer type name of an l2.Client for assertion.
func typeName(c l2.Client) string {
	switch c.(type) {
	case *l2.AnthropicClient:
		return "*l2.AnthropicClient"
	case *l2.OpenAICompatClient:
		return "*l2.OpenAICompatClient"
	default:
		return "unknown"
	}
}
