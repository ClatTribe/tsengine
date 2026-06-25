package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func riskDeps(t *testing.T) (Deps, *ledger.Recorder) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.PutTenant(ctx, platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	// two high+ findings in the Injection category → one candidate risk
	_ = st.PutFinding(ctx, "ten-1", types.Finding{ID: "f1", Tool: "sqlmap", Severity: types.SeverityCritical, CWE: []string{"CWE-89"}})
	_ = st.PutFinding(ctx, "ten-1", types.Finding{ID: "f2", Tool: "nuclei", Severity: types.SeverityHigh, CWE: []string{"CWE-79"}})
	n := 0
	rec := ledger.NewRecorder()
	return Deps{Store: st, Recorder: rec, NewID: func() string { n++; return fmt.Sprintf("r%d", n) }}, rec
}

func call(d Deps, h func(http.ResponseWriter, *http.Request, string), method, path, body, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	h(rec, req, "ten-1")
	return rec
}

func TestRisks_SeedThenHumanDecision(t *testing.T) {
	d, rec := riskDeps(t)

	// 1) seed candidates from findings → one Injection risk, proposed, grounded
	srec := call(d, d.handleSeedRisks, http.MethodPost, "/v1/risks/seed", "", "")
	if srec.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", srec.Code, srec.Body.String())
	}
	var seedOut struct {
		Seeded []platform.Risk `json:"seeded"`
	}
	_ = json.Unmarshal(srec.Body.Bytes(), &seedOut)
	if len(seedOut.Seeded) != 1 || seedOut.Seeded[0].ID != "risk-injection" || !seedOut.Seeded[0].Proposed {
		t.Fatalf("want 1 proposed injection candidate, got %+v", seedOut.Seeded)
	}

	// 2) decision requires a named owner + valid treatment
	if r := call(d, d.handleDecideRisk, http.MethodPost, "/x", `{"treatment":"accept"}`, "risk-injection"); r.Code != http.StatusBadRequest {
		t.Errorf("decision without owner must be 400, got %d", r.Code)
	}
	if r := call(d, d.handleDecideRisk, http.MethodPost, "/x", `{"treatment":"nonsense","owner":"Jane"}`, "risk-injection"); r.Code != http.StatusBadRequest {
		t.Errorf("invalid treatment must be 400, got %d", r.Code)
	}

	// 3) a named human accepts the residual risk → accepted, no longer proposed, ledger-recorded
	drec := call(d, d.handleDecideRisk, http.MethodPost, "/x", `{"treatment":"accept","owner":"Jane Doe (CISO)","rationale":"compensating WAF"}`, "risk-injection")
	if drec.Code != http.StatusOK {
		t.Fatalf("decision: %d %s", drec.Code, drec.Body.String())
	}
	var decided platform.Risk
	_ = json.Unmarshal(drec.Body.Bytes(), &decided)
	if decided.Status != platform.RiskAccepted || decided.Proposed || decided.DecidedBy != "Jane Doe (CISO)" || decided.LedgerRef == "" {
		t.Fatalf("expected accepted+decided+ledgered risk, got %+v", decided)
	}
	if len(rec.Steps()) == 0 {
		t.Error("the human decision must be recorded into the ledger")
	}

	// 4) re-seeding must NOT clobber the human's decision
	srec2 := call(d, d.handleSeedRisks, http.MethodPost, "/v1/risks/seed", "", "")
	var seed2 struct {
		Seeded []platform.Risk `json:"seeded"`
	}
	_ = json.Unmarshal(srec2.Body.Bytes(), &seed2)
	if len(seed2.Seeded) != 0 {
		t.Errorf("re-seed should skip the decided risk, got %+v", seed2.Seeded)
	}
	risks, _ := d.Store.ListRisks(context.Background(), "ten-1")
	if len(risks) != 1 || risks[0].Status != platform.RiskAccepted {
		t.Errorf("decision must persist through re-seed, got %+v", risks)
	}
}

func TestRisks_ListWithSummary(t *testing.T) {
	d, _ := riskDeps(t)
	_ = call(d, d.handleSeedRisks, http.MethodPost, "/v1/risks/seed", "", "")
	lrec := call(d, d.handleListRisks, http.MethodGet, "/v1/risks", "", "")
	var out struct {
		Risks   []platform.Risk `json:"risks"`
		Summary map[string]any  `json:"summary"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &out)
	if len(out.Risks) != 1 || out.Summary["total"].(float64) != 1 || out.Summary["proposed"].(float64) != 1 {
		t.Fatalf("list+summary wrong: risks=%+v summary=%+v", out.Risks, out.Summary)
	}
}
