package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestLLMSettings_SelfHostedOllama(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	h := NewHandler(d)

	// A self-hosted provider without a base_url is refused.
	if r := do(h, "PUT", "/v1/settings/llm", "t1", `{"provider":"ollama","model":"llama3.1"}`); r.Code != 400 {
		t.Errorf("ollama without base_url → 400, got %d: %s", r.Code, r.Body.String())
	}
	// With a base_url and NO key it's accepted (Ollama needs no key).
	if r := do(h, "PUT", "/v1/settings/llm", "t1", `{"provider":"ollama","model":"llama3.1","base_url":"http://localhost:11434/v1"}`); r.Code != 200 {
		t.Fatalf("ollama with base_url → 200, got %d: %s", r.Code, r.Body.String())
	}
	// GET echoes the base_url (an endpoint, not a secret).
	if g := do(h, "GET", "/v1/settings/llm", "t1", "").Body.String(); !strings.Contains(g, "localhost:11434") {
		t.Errorf("GET should report base_url, got %s", g)
	}
	// And it RESOLVES to a live agent LLM — the whole point (previously a keyless/self-hosted config
	// would never drive the pentest).
	if d.resolveAgentLLM(ctx, "t1") == nil {
		t.Error("a self-hosted ollama config should resolve to a live agent LLM (keyless)")
	}
}
