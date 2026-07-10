package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestResolveLeadClient_ThreadsBaseURL proves the wiring the whole "use the proxy as the frontend LLM"
// flow depends on: a tenant configured with an openai-compat provider + a base_url (the dev file-relay
// proxy, or a self-hosted endpoint) must drive the L2 LEAD (Triage/Investigate/narrative) AT THAT URL —
// not the vendor default. Before the fix, resolveLeadClient passed "" for the base URL, so a
// proxy-configured tenant silently hit api.openai.com and never reached the proxy. (The per-provider
// selection is covered by TestResolveLeadClient_PerTenantProviders; this is the wire-level base-URL proof.)
func TestResolveLeadClient_ThreadsBaseURL(t *testing.T) {
	ctx := context.Background()
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`))
	}))
	defer srv.Close()

	st := store.NewMemory()
	// a keyless self-hosted / proxy config (SelfHosted → no key needed), pointed at the fake endpoint.
	_ = st.PutTenant(ctx, platform.Tenant{
		ID: "t1", Plan: platform.PlanEnterprise,
		LLM: &platform.LLMConfig{Provider: "openai-compat", Model: "claude-proxy", BaseURL: srv.URL},
	})
	d := Deps{Store: st}

	c := d.resolveLeadClient(ctx, "t1")
	if c == nil {
		t.Fatal("a tenant with a self-hosted/proxy endpoint must resolve a Lead client")
	}
	_, _ = c.Generate(ctx, "you are a security engineer", []l2.Message{{Role: "user", Content: "triage"}}, nil)
	if !hit {
		t.Fatal("the resolved Lead client must send its request to the configured base_url (the proxy), not the vendor default — the base URL wasn't threaded")
	}
}
