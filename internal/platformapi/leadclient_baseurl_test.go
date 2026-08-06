package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// leadTenant stores a tenant whose LLM config points at a self-hosted endpoint.
func leadTenant(t *testing.T, provider, model, baseURL string) Deps {
	t.Helper()
	st := store.NewMemory()
	// A KeyRef + idSealer vault so CLOUD providers resolve: resolveTenantLLMConfig requires either a
	// key or a self-hosted endpoint ("a config with neither can't drive anything"), which is correct —
	// a keyless cloud config is unusable. Self-hosted cases below carry a BaseURL instead.
	err := st.PutTenant(context.Background(), platform.Tenant{
		ID: "t1", Name: "Acme", Plan: platform.PlanFree, // Free on purpose: a tenant's OWN model is allowed on any plan
		LLM: &platform.LLMConfig{Provider: provider, Model: model, BaseURL: baseURL, KeyRef: "tenant-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st, Token: "platform-tok", Vault: idSealer{}}
}

// THE BUG (#1005). resolveLeadClient used ResolveTenantLLM, which returns only (provider, model, key)
// and DROPS cfg.BaseURL — so a tenant running Ollama/vLLM/LM Studio had their requests sent to the
// OpenAI default instead of their own endpoint. Silent: the config looked accepted, the switch even
// listed their provider, and nothing surfaced the drop.
func TestResolveLeadClient_ThreadsSelfHostedBaseURL(t *testing.T) {
	const endpoint = "http://ollama.internal:11434/v1"
	for _, provider := range []string{"ollama", "vllm", "lmstudio", "openrouter", "openai-compat"} {
		d := leadTenant(t, provider, "qwen2.5", endpoint)
		c := d.resolveLeadClient(context.Background(), "t1")
		if c == nil {
			t.Fatalf("%s: expected a client for a tenant's own model on any plan", provider)
		}
		oc, ok := c.(*l2.OpenAICompatClient)
		if !ok {
			t.Fatalf("%s: expected an OpenAI-compatible client, got %T", provider, c)
		}
		if got := oc.BaseURL(); got != endpoint {
			t.Errorf("%s: base URL = %q, want the tenant's own %q — a self-hosted endpoint must be reached",
				provider, got, endpoint)
		}
	}
}

// An unset BaseURL must keep the vendor default rather than becoming an empty, unroutable endpoint.
func TestResolveLeadClient_EmptyBaseURLKeepsVendorDefault(t *testing.T) {
	d := leadTenant(t, "openai", "gpt-5", "")
	c := d.resolveLeadClient(context.Background(), "t1")
	oc, ok := c.(*l2.OpenAICompatClient)
	if !ok {
		t.Fatalf("expected an OpenAI-compatible client, got %T", c)
	}
	if oc.BaseURL() == "" {
		t.Error("an unset BaseURL should fall back to the vendor default, not stay empty")
	}
}

// Gemini keeps its OpenAI-compatible surface by default, but an explicitly configured endpoint must
// still win — a tenant fronting Gemini with their own proxy has to be reachable.
func TestResolveLeadClient_ExplicitBaseURLBeatsGeminiDefault(t *testing.T) {
	const proxy = "https://llm-proxy.acme.internal/v1"
	d := leadTenant(t, "gemini", "gemini-2.0-flash", proxy)
	oc, ok := d.resolveLeadClient(context.Background(), "t1").(*l2.OpenAICompatClient)
	if !ok {
		t.Fatal("expected an OpenAI-compatible client for gemini")
	}
	if got := oc.BaseURL(); got != proxy {
		t.Errorf("explicit BaseURL must win over the vendor default: got %q, want %q", got, proxy)
	}

	// ...and with none set, the Gemini default is used.
	d2 := leadTenant(t, "gemini", "gemini-2.0-flash", "")
	oc2, _ := d2.resolveLeadClient(context.Background(), "t1").(*l2.OpenAICompatClient)
	if oc2 == nil || oc2.BaseURL() == proxy || oc2.BaseURL() == "" {
		t.Errorf("unset BaseURL should use the Gemini OpenAI-compatible default, got %v", oc2)
	}
}

// Anthropic has no OpenAI-compatible base URL to thread; it must still resolve to a Claude client.
func TestResolveLeadClient_AnthropicUnaffected(t *testing.T) {
	d := leadTenant(t, "anthropic", "claude-opus-4-5", "")
	if _, ok := d.resolveLeadClient(context.Background(), "t1").(*l2.AnthropicClient); !ok {
		t.Error("an anthropic tenant should get the Claude client")
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("", "fallback"); got != "fallback" {
		t.Errorf("empty should take the default, got %q", got)
	}
	if got := orDefault("   ", "fallback"); got != "fallback" {
		t.Errorf("whitespace-only should take the default, got %q", got)
	}
	if got := orDefault("set", "fallback"); got != "set" {
		t.Errorf("a set value must win, got %q", got)
	}
}
