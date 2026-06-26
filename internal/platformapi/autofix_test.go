package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestBuildAutofixPrompt_GroundsInTheFinding(t *testing.T) {
	f := types.Finding{
		ID: "f-1", RuleID: "semgrep::sql-injection", Tool: "semgrep", Severity: types.SeverityHigh,
		CWE: []string{"CWE-89"}, Endpoint: "internal/db/users.go:42", Title: "SQL injection via string concat",
		Description: "user input concatenated into a query",
	}
	p := buildAutofixPrompt(f)
	for _, want := range []string{"semgrep::sql-injection", "CWE-89", "internal/db/users.go:42", "do NOT invent", "corrected code"} {
		if !strings.Contains(p, want) {
			t.Errorf("autofix prompt missing %q", want)
		}
	}
}

func TestAutofix_GatedAndNotFound(t *testing.T) {
	st := store.NewMemory()
	// No LLM → 400.
	d0 := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	if rec := do(NewHandler(d0), "POST", "/v1/findings/f-x/autofix", "t1", "{}"); rec.Code != 400 {
		t.Fatalf("no LLM → 400, got %d: %s", rec.Code, rec.Body.String())
	}
	// With an LLM but unknown finding → 404.
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: fakeCloudLLM{}}
	if rec := do(NewHandler(d), "POST", "/v1/findings/missing/autofix", "t1", "{}"); rec.Code != 404 {
		t.Fatalf("unknown finding → 404, got %d", rec.Code)
	}
	// With an LLM + a real finding → 200 + a fix.
	_ = st.PutFinding(context.Background(), "t1", types.Finding{ID: "f-1", RuleID: "semgrep::xss", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "app.js:10", Title: "XSS"})
	if rec := do(NewHandler(d), "POST", "/v1/findings/f-1/autofix", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("autofix should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
