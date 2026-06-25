package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestOperator_ActOnBehalf_DecideRisk proves the act-on-behalf path: an operator (the managed/MSP
// expert) decides a risk for an ASSIGNED client from their console, the decision records their
// capacity + firm from the roster, and is ledger-signed — while an UNASSIGNED client is refused (403)
// and left untouched (tenant isolation, §18.2 inv. 2).
func TestOperator_ActOnBehalf_DecideRisk(t *testing.T) {
	d := operatorDeps(t)
	d.Recorder = ledger.NewRecorder()

	// dana is provisioned + logs in
	if r := callRaw(d.handleCreateOperator, http.MethodPost, `{"email":"dana@x.io","name":"Dana","firm":"TS Managed","password":"sup3rsecret"}`); r.Code != http.StatusOK {
		t.Fatalf("create operator: %d %s", r.Code, r.Body.String())
	}
	lrec := callRaw(d.handleOperatorLogin, http.MethodPost, `{"email":"dana@x.io","password":"sup3rsecret"}`)
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &login)

	act := d.operatorAuth(d.handleOperatorDecideRisk)

	// (1) dana decides tenant A's risk ra (she IS the practitioner of record) → 200, capacity managed
	decided := decideAsOperator(t, act, login.Token, "tA", "ra", `{"treatment":"mitigate","rationale":"compensating controls in place"}`)
	if decided.Code != http.StatusOK {
		t.Fatalf("act-on-behalf on assigned client: %d %s", decided.Code, decided.Body.String())
	}
	var rk platform.Risk
	_ = json.Unmarshal(decided.Body.Bytes(), &rk)
	if rk.Capacity != platform.CapacityManaged || rk.Firm != "TS Managed" {
		t.Errorf("decision must record the operator's roster capacity/firm, got %q/%q", rk.Capacity, rk.Firm)
	}
	if rk.DecidedBy != "Dana" || rk.Owner != "Dana" || rk.Proposed {
		t.Errorf("decision must name the operator as the human owner + drop proposed, got DecidedBy=%q Owner=%q Proposed=%v", rk.DecidedBy, rk.Owner, rk.Proposed)
	}
	if rk.Treatment != platform.RiskTreatmentMitigate || rk.LedgerRef == "" {
		t.Errorf("decision must apply the treatment + be ledger-signed, got treatment=%q ledger=%q", rk.Treatment, rk.LedgerRef)
	}

	// (2) ISOLATION: dana is NOT a practitioner for tenant B → 403, and rb is left untouched
	forbidden := decideAsOperator(t, act, login.Token, "tB", "rb", `{"treatment":"accept"}`)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("act-on-behalf on an UNASSIGNED client must be 403, got %d %s", forbidden.Code, forbidden.Body.String())
	}
	rbs, _ := d.Store.ListRisks(context.Background(), "tB")
	for _, rb := range rbs {
		if rb.ID == "rb" && (rb.DecidedBy != "" || !rb.Proposed) {
			t.Errorf("ISOLATION: the unassigned client's risk must be untouched, got DecidedBy=%q Proposed=%v", rb.DecidedBy, rb.Proposed)
		}
	}

	// (3) an invalid treatment on an assigned client is still a 400 (validation shared with the tenant path)
	if bad := decideAsOperator(t, act, login.Token, "tA", "ra", `{"treatment":"ignore"}`); bad.Code != http.StatusBadRequest {
		t.Errorf("invalid treatment must be 400, got %d", bad.Code)
	}
}

func decideAsOperator(t *testing.T, h http.HandlerFunc, token, tenant, risk, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/"+tenant+"/risks/"+risk+"/decision", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("tenant", tenant)
	req.SetPathValue("id", risk)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}
