package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func agentSetup(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Name: "Acme"})
	return NewHandler(Deps{Store: st, Token: "platform-tok"}), st
}

const shadowAgent = `{"agents":[{
  "name":"cursor","user":"dev@acme.io","model":"gpt-5","sanctioned":false,"autonomy":"auto-approve",
  "mcp_servers":[{"name":"rando-tool","source":"rando/tool@latest","pinned":false,"verified":false}],
  "tool_use":[{"tool":"Read","target":"/Users/dev/.aws/credentials"}]
}]}`

func TestAgentPostureIngest_StoresGroundedFindings(t *testing.T) {
	h, st := agentSetup(t)

	rec := do(h, http.MethodPost, "/v1/agents/ingest", "t1", shadowAgent)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Agents int `json:"agents"`
		Issues int `json:"issues_detected"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Agents != 1 || body.Issues == 0 {
		t.Fatalf("expected findings for an ungoverned agent: %+v", body)
	}

	// The findings must actually land in the store, so they flow through issues/incidents/grc.
	fs, err := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != body.Issues {
		t.Fatalf("stored %d findings, response reported %d", len(fs), body.Issues)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.RuleID] = true
		if f.Endpoint == "" || f.Compliance == nil {
			t.Errorf("finding not grounded: %+v", f)
		}
	}
	for _, want := range []string{
		"agentposture::unsanctioned-agent",
		"agentposture::auto-approve",
		"agentposture::unpinned-mcp",
		"agentposture::secret-path-access",
	} {
		if !seen[want] {
			t.Errorf("missing %s (got %v)", want, keysOf(seen))
		}
	}
}

// A governed estate must store nothing — the FP-control property, end to end through the API.
func TestAgentPostureIngest_GovernedEstateStoresNothing(t *testing.T) {
	h, st := agentSetup(t)
	governed := `{"agents":[{"name":"claude-code","user":"ada@acme.io","model":"claude-opus-4-5",
	  "sanctioned":true,"autonomy":"supervised",
	  "mcp_servers":[{"name":"acme","source":"acme/x@sha256:1","pinned":true,"verified":true}],
	  "tool_use":[{"tool":"Read","target":"src/main.go"}]}]}`

	if rec := do(h, http.MethodPost, "/v1/agents/ingest", "t1", governed); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) != 0 {
		t.Fatalf("a governed agent estate must produce zero findings, got %d: %+v", len(fs), fs)
	}
}

func TestAgentPostureIngest_RejectsMalformedBody(t *testing.T) {
	h, _ := agentSetup(t)
	if rec := do(h, http.MethodPost, "/v1/agents/ingest", "t1", `{"agents":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for malformed JSON, got %d", rec.Code)
	}
}

// Tenant isolation (§18.2 inv. 2): an ingest for one tenant must not be visible to another.
func TestAgentPostureIngest_TenantIsolation(t *testing.T) {
	h, st := agentSetup(t)
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t2", Name: "Other"})

	if rec := do(h, http.MethodPost, "/v1/agents/ingest", "t1", shadowAgent); rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d", rec.Code)
	}
	other, _ := st.ListFindings(context.Background(), "t2", store.FindingFilter{})
	if len(other) != 0 {
		t.Fatalf("tenant t2 can see t1's agent findings: %+v", other)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
