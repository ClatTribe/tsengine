package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// END TO END: a leaked-key finding from the CODE surface becomes a stored, enriched cross-surface
// finding a customer can actually see — the whole point of composing the graph in the platform.
func TestEstate_DetectionReachesTheCustomer(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// gitleaks-shaped finding: the key id lives in the finding's OWN text, which is what
	// FromLeakedSecrets extracts (never the rule name).
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-leak", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks",
		Severity: types.SeverityHigh, Endpoint: "repo/app.py",
		Title: "AWS access key committed", Description: "AKIAIOSFODNN7EXAMPLE found in app.py",
	})

	// The graph is composable and reports honestly that one surface cannot be joined.
	g := do(h, "GET", "/v1/estate", "t1", "")
	if g.Code != 200 {
		t.Fatalf("GET /v1/estate: %d %s", g.Code, g.Body.String())
	}
	if !strings.Contains(g.Body.String(), `"joinable":false`) {
		t.Errorf("with only the code surface present, joinable must be false: %s", g.Body.String())
	}

	// Detection runs and persists through the normal pipeline.
	rec := do(h, "POST", "/v1/estate/detect", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("POST /v1/estate/detect: %d %s", rec.Code, rec.Body.String())
	}

	// A code-only estate has nothing to JOIN, so it must detect nothing — the honest answer, and
	// the guard against this endpoint inventing cross-surface drama from one surface.
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	for _, f := range stored {
		if strings.HasPrefix(f.RuleID, "estate::") {
			t.Errorf("a single-surface estate produced a cross-surface finding %q", f.RuleID)
		}
	}
}

// Tenant isolation: one tenant's estate must never be composed from another's findings.
func TestEstate_IsTenantIsolated(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()
	_ = st.PutFinding(ctx, "t2", types.Finding{
		ID: "f-other", Tool: "gitleaks", Endpoint: "other/app.py",
		Description: "AKIAIOSFODNN7EXAMPLE found", Severity: types.SeverityHigh,
	})
	body := do(h, "GET", "/v1/estate", "t1", "").Body.String()
	if strings.Contains(body, "other/app.py") || strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("t1's estate leaked t2's data: %s", body)
	}
	if !strings.Contains(body, `"node_count":0`) {
		t.Errorf("a tenant with nothing of its own must compose an empty graph, got %s", body)
	}
}
