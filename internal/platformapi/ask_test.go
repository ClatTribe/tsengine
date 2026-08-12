package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// T6 was reachable by the AGENT and by nobody else. These cover the human door, and the first one is
// the reason the handler reuses the agent's adapter instead of implementing its own query.

func askDeps(t *testing.T) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []types.Finding{
		{ID: "f-log4j", Tool: "grype", RuleID: "CVE-2021-44228", Severity: types.SeverityCritical,
			Title:       "Remote code execution in logging library",
			Endpoint:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			Description: "The bundled version is affected by the JNDI lookup flaw."},
		{ID: "f-hsts", Tool: "nuclei", RuleID: "missing-hsts", Severity: types.SeverityLow,
			Title: "Missing HSTS header", Endpoint: "https://a.example/"},
	} {
		if err := st.PutFinding(ctx, tid, f); err != nil {
			t.Fatal(err)
		}
	}
	return Deps{Store: st}, tid
}

func ask(t *testing.T, d Deps, tid, q string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleAsk(rec, httptest.NewRequest(http.MethodGet, "/v1/ask?q="+strings.ReplaceAll(q, " ", "+"), nil), tid)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// THE ONE THAT MATTERS. The human endpoint and the agent's tool must return the SAME answer. Two
// implementations would drift, and then the dashboard and the agent would disagree about the customer's
// own estate — the one thing a security product cannot have two answers for.
func TestAsk_HumanAndAgentGetTheSameAnswer(t *testing.T) {
	d, tid := askDeps(t)
	const q = "log4j"

	_, body := ask(t, d, tid, q)
	viaHTTP, _ := body["answer"].(string)

	viaAgent, err := (estateSearch{d: d, tenantID: tid}).Search(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if viaHTTP != viaAgent {
		t.Errorf("DRIFT: the human endpoint and the agent tool answered differently.\nHTTP:  %s\nAGENT: %s",
			viaHTTP, viaAgent)
	}
	if !strings.Contains(viaHTTP, "f-log4j") {
		t.Errorf("the log4j finding was not returned:\n%s", viaHTTP)
	}
}

// A question with no query is a mistake worth naming, not an empty answer that reads as "you're clean".
func TestAsk_EmptyQueryIsRefusedNotAnsweredEmpty(t *testing.T) {
	d, tid := askDeps(t)
	code, _ := ask(t, d, tid, "")
	if code != http.StatusBadRequest {
		t.Errorf("empty query returned %d — an empty answer reads as 'nothing found', which is a false "+
			"all-clear about the estate", code)
	}
}

// Tenant isolation (§18.2 inv. 2): the query never carries a tenant, so no input can cross the boundary.
func TestAsk_CannotReachAnotherTenant(t *testing.T) {
	ctx := context.Background()
	d, tid := askDeps(t)
	if err := d.Store.PutTenant(ctx, platform.Tenant{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.PutFinding(ctx, "other", types.Finding{
		ID: "f-secret", Title: "Other tenant's critical", Severity: types.SeverityCritical,
	}); err != nil {
		t.Fatal(err)
	}
	_, body := ask(t, d, tid, "critical")
	if a, _ := body["answer"].(string); strings.Contains(a, "f-secret") {
		t.Errorf("ISOLATION: another tenant's finding was returned:\n%s", a)
	}
}

// An overlong question answers rather than erroring — someone pastes a stack trace into the box.
func TestAsk_LongQueryIsTruncatedNotRefused(t *testing.T) {
	d, tid := askDeps(t)
	code, _ := ask(t, d, tid, strings.Repeat("log4j ", 200))
	if code != http.StatusOK {
		t.Errorf("a long query returned %d, want 200 — pasting a stack trace should still answer", code)
	}
}
