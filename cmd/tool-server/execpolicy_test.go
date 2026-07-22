package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/execpolicy"
	"github.com/ClatTribe/tsengine/internal/tool"
)

// fakeTool is a no-op registered tool so the ALLOW path reaches an actual run.
type fakeTool struct{ name string }

func (f fakeTool) Name() string              { return f.name }
func (f fakeTool) SandboxExecution() bool    { return true }
func (f fakeTool) MITRETechniques() []string { return nil }
func (f fakeTool) Run(context.Context, tool.Args) (tool.Result, error) {
	return tool.Result{}, nil
}

func post(h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(string(b)))
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

// TestExecHandler_EnforcesCapability is the zero-trust proof: with a spawn-time policy, the tool-server
// itself refuses an out-of-scope tool or target — even though the caller holds the bearer token. This
// is the "reject even if the orchestrator is compromised or miswired" property.
func TestExecHandler_EnforcesCapability(t *testing.T) {
	tool.Register(fakeTool{name: "scan-tool"})
	policy := &execpolicy.Policy{Tools: []string{"scan-tool"}, Hosts: []string{"app.acme.com"}, MaxRequests: 2}
	h := execHandler(policy)

	// in-policy tool + in-scope target → runs (200)
	if w := post(h, map[string]any{"tool": "scan-tool", "args": map[string]any{"target": "https://app.acme.com/x"}}); w.Code != 200 {
		t.Errorf("in-policy dispatch should run, got %d: %s", w.Code, w.Body)
	}
	// a tool NOT in the policy → 403 (not 404 — refused before we even resolve it)
	if w := post(h, map[string]any{"tool": "sqlmap", "args": map[string]any{"target": "https://app.acme.com/x"}}); w.Code != http.StatusForbidden {
		t.Errorf("out-of-policy tool must be 403, got %d", w.Code)
	}
	// the in-scope tool aimed at cloud metadata (the incident's escape) → 403
	if w := post(h, map[string]any{"tool": "scan-tool", "args": map[string]any{"target": "http://169.254.169.254/latest/meta-data/"}}); w.Code != http.StatusForbidden {
		t.Errorf("metadata target must be 403, got %d", w.Code)
	}
	// the in-scope tool aimed at an off-scope internal host → 403
	if w := post(h, map[string]any{"tool": "scan-tool", "args": map[string]any{"target": "https://internal-db.acme.local/"}}); w.Code != http.StatusForbidden {
		t.Errorf("off-scope target must be 403, got %d", w.Code)
	}
}

// TestExecHandler_Budget: only 2 authorized runs are allowed; the 3rd is refused. Denied dispatches
// (403) don't consume the budget — so a scan isn't starved by an attacker spamming out-of-scope calls.
func TestExecHandler_Budget(t *testing.T) {
	tool.Register(fakeTool{name: "budget-tool"})
	h := execHandler(&execpolicy.Policy{Tools: []string{"budget-tool"}, MaxRequests: 2})
	ok := map[string]any{"tool": "budget-tool"}
	for i := 0; i < 2; i++ {
		if w := post(h, ok); w.Code != 200 {
			t.Fatalf("run %d within budget should pass, got %d", i, w.Code)
		}
	}
	// a rejected out-of-policy call in between must NOT count against the budget
	_ = post(h, map[string]any{"tool": "not-allowed"})
	if w := post(h, ok); w.Code != http.StatusForbidden {
		t.Errorf("3rd authorized run must be over budget (403), got %d", w.Code)
	}
}

// TestExecHandler_NilPolicyPermissive: back-compat — no policy runs any registered tool (dev).
func TestExecHandler_NilPolicyPermissive(t *testing.T) {
	tool.Register(fakeTool{name: "free-tool"})
	h := execHandler(nil)
	if w := post(h, map[string]any{"tool": "free-tool", "args": map[string]any{"target": "http://anywhere"}}); w.Code != 200 {
		t.Errorf("nil policy should be permissive, got %d", w.Code)
	}
}
