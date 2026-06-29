package platformapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Regression for the Investigate 404 (found by dogfooding, fixed in the key-in-body PR): an issue key is
// rule_id|endpoint, where the endpoint is a URL/ARN that contains '/'. Such a key CANNOT ride in a Go
// ServeMux {key} path segment — a '%2F' breaks route matching, so the original POST /v1/issues/{key}/...
// 404'd for nearly every issue. The key now goes in the BODY. unit tests + tsc were all green when this
// shipped broken; only a real HTTP click surfaced it. This guards the body-key contract at the handler.
func TestIssueInvestigate_SlashKeyInBodyReturns200(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	// A web finding whose endpoint is a URL → its unified-issue key contains slashes (the exact shape
	// that broke the old path-segment route).
	f := types.Finding{
		ID: "f-1", RuleID: "nuclei::sqli-error-based", Severity: types.SeverityCritical,
		Title: "SQL injection", Endpoint: "https://api.northwind.io/v2/search?q=",
	}
	if err := st.PutFinding(ctx, "ten-1", f); err != nil {
		t.Fatal(err)
	}
	// Resolve the key the SAME way the handler does, so the test isn't coupled to the key format.
	issues := crossdetect.UnifiedIssues([]types.Finding{f})
	if len(issues) != 1 {
		t.Fatalf("want 1 unified issue, got %d", len(issues))
	}
	key := issues[0].Key
	if !strings.Contains(key, "/") {
		t.Fatalf("test premise broken — the issue key must contain a slash to exercise the bug, got %q", key)
	}

	// No LLM client wired → the handler takes the deterministic-only path (graceful degrade), so this
	// runs without a model: it still must find the issue and return 200, never 404.
	d := Deps{Store: st}
	body, _ := json.Marshal(map[string]string{"key": key})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/issues/investigate", bytes.NewReader(body))
	d.handleIssueInvestigate(rec, req, "ten-1")

	if rec.Code != http.StatusOK {
		t.Fatalf("a slash-key investigate must return 200 (was 404 when the key rode the path); got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["issue"] == nil {
		t.Error("response should echo the resolved issue")
	}
	if resp["ai_enabled"] != false {
		t.Errorf("with no LLM configured, ai_enabled should be false (deterministic half only), got %v", resp["ai_enabled"])
	}
}

// A missing/empty key is a 400, never a 404 or a panic.
func TestIssueInvestigate_MissingKey400(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"})
	d := Deps{Store: st}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/issues/investigate", strings.NewReader(`{}`))
	d.handleIssueInvestigate(rec, req, "ten-1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key should be 400, got %d", rec.Code)
	}
}
