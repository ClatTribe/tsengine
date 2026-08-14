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

// T2 was reachable by the AGENT and by nobody else. These cover the human door — and the first one is
// why the handler reuses the agent's adapter rather than implementing its own ranking.

func localizeDeps(t *testing.T) (Deps, string) {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	const tid = "t1"
	if err := st.PutTenant(ctx, platform.Tenant{ID: tid}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutFinding(ctx, tid, types.Finding{
		ID: "f-sqli", Tool: "semgrep", RuleID: "sql-injection", Severity: types.SeverityCritical,
		Title: "SQL injection", CWE: []string{"CWE-89"},
	}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st}, tid
}

func localize(t *testing.T, d Deps, tid, id string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/findings/"+id+"/localize", nil)
	req.SetPathValue("id", id)
	d.handleLocalize(rec, req, tid)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// THE ONE THAT MATTERS: one answer, not two. A separate human-facing implementation would drift, and
// then the agent and the dashboard would disagree about where the bug is.
func TestLocalize_HumanAndAgentGetTheSameAnswer(t *testing.T) {
	d, tid := localizeDeps(t)
	_, body := localize(t, d, tid, "f-sqli")
	viaHTTP, _ := body["answer"].(string)

	viaAgent, err := (vulnLocalizer{d: d, tenantID: tid}).Locate(context.Background(), "f-sqli")
	if err != nil {
		t.Fatal(err)
	}
	if viaHTTP != viaAgent {
		t.Errorf("DRIFT: endpoint and agent tool answered differently.\nHTTP:  %s\nAGENT: %s", viaHTTP, viaAgent)
	}
}

// With no repository connected the answer must say SO — and must say it is not a verdict on the
// finding. Rendering "we found nothing" for "we could not look" is the same false all-clear the estate
// query guards against.
func TestLocalize_NoRepoSaysSoAndDoesNotJudgeTheFinding(t *testing.T) {
	d, tid := localizeDeps(t)
	code, body := localize(t, d, tid, "f-sqli")
	if code != http.StatusOK {
		t.Fatalf("code=%d", code)
	}
	a, _ := body["answer"].(string)
	if !strings.Contains(strings.ToLower(a), "connect a repository") {
		t.Errorf("a tenant with no repo should be told localization needs source access, got: %s", a)
	}
	if !strings.Contains(strings.ToLower(a), "not a statement about the finding") {
		t.Errorf("the no-source answer must say it is NOT a verdict on the finding — otherwise it reads "+
			"as 'nothing here', which is a false all-clear. Got: %s", a)
	}
}

// A finding that isn't ours must not resolve (§18.2 inv. 2).
func TestLocalize_CannotReachAnotherTenantsFinding(t *testing.T) {
	ctx := context.Background()
	d, tid := localizeDeps(t)
	if err := d.Store.PutTenant(ctx, platform.Tenant{ID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.PutFinding(ctx, "other", types.Finding{ID: "f-secret", Title: "Theirs"}); err != nil {
		t.Fatal(err)
	}
	code, _ := localize(t, d, tid, "f-secret")
	if code == http.StatusOK {
		t.Error("ISOLATION: another tenant's finding was localizable")
	}
}
