package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/pentest"
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

	// (4) act-on-behalf also covers policy publish (the other vCISO deliverable)
	ctx := context.Background()
	_ = d.Store.PutPolicy(ctx, platform.Policy{ID: "pa", TenantID: "tA", Name: "Access Control Policy", Status: platform.PolicyDraft})
	_ = d.Store.PutPolicy(ctx, platform.Policy{ID: "pb", TenantID: "tB", Name: "Other policy", Status: platform.PolicyDraft})
	pub := d.operatorAuth(d.handleOperatorPublishPolicy)

	// dana publishes tenant A's draft policy → 200, managed capacity, published + ledger-signed
	prec := publishAsOperator(t, pub, login.Token, "tA", "pa")
	if prec.Code != http.StatusOK {
		t.Fatalf("publish-on-behalf on assigned client: %d %s", prec.Code, prec.Body.String())
	}
	var pol platform.Policy
	_ = json.Unmarshal(prec.Body.Bytes(), &pol)
	if pol.Status != platform.PolicyPublished || pol.Owner != "Dana" || pol.Capacity != platform.CapacityManaged || pol.LedgerRef == "" {
		t.Errorf("publish must set published + named owner + managed capacity + ledger, got status=%q owner=%q cap=%q ledger=%q", pol.Status, pol.Owner, pol.Capacity, pol.LedgerRef)
	}

	// ISOLATION: dana cannot publish tenant B's policy → 403, left a draft
	if f := publishAsOperator(t, pub, login.Token, "tB", "pb"); f.Code != http.StatusForbidden {
		t.Fatalf("publish-on-behalf on an UNASSIGNED client must be 403, got %d", f.Code)
	}
	pbs, _ := d.Store.ListPolicies(ctx, "tB")
	for _, p := range pbs {
		if p.ID == "pb" && p.Status != platform.PolicyDraft {
			t.Errorf("ISOLATION: the unassigned client's policy must stay a draft, got %q", p.Status)
		}
	}

	// (5) act-on-behalf also covers pentest sign-off (named accountability on a pentest)
	_ = d.Store.PutPentest(ctx, pentest.Engagement{ID: "ea", TenantID: "tA", Name: "Q3 VAPT", Status: pentest.StatusComplete})
	_ = d.Store.PutPentest(ctx, pentest.Engagement{ID: "eb", TenantID: "tB", Name: "Other VAPT", Status: pentest.StatusComplete})
	sign := d.operatorAuth(d.handleOperatorSignoffPentest)

	srec := signoffAsOperator(t, sign, login.Token, "tA", "ea", `{"role":"Lead Pentester","statement":"Reviewed all proven findings."}`)
	if srec.Code != http.StatusOK {
		t.Fatalf("signoff-on-behalf on assigned client: %d %s", srec.Code, srec.Body.String())
	}
	var eng pentest.Engagement
	_ = json.Unmarshal(srec.Body.Bytes(), &eng)
	if eng.Signoff == nil || eng.Signoff.Signer != "Dana" || eng.Signoff.Capacity != platform.CapacityManaged || eng.Signoff.LedgerRef == "" {
		t.Errorf("signoff must name the operator + record managed capacity + ledger, got %+v", eng.Signoff)
	}

	// ISOLATION: dana cannot sign off tenant B's report → 403, left unsigned
	if f := signoffAsOperator(t, sign, login.Token, "tB", "eb", `{}`); f.Code != http.StatusForbidden {
		t.Fatalf("signoff-on-behalf on an UNASSIGNED client must be 403, got %d", f.Code)
	}
	ebg, _ := d.Store.GetPentest(ctx, "tB", "eb")
	if ebg.Signoff != nil {
		t.Errorf("ISOLATION: the unassigned client's report must stay unsigned, got %+v", ebg.Signoff)
	}

	// (6) act-on-behalf also covers audit control-attestation (independent legal attestation)
	_ = d.Store.PutAuditEngagement(ctx, platform.AuditEngagement{ID: "aa", TenantID: "tA", Framework: "soc2", Status: platform.AuditPlanning,
		Attestations: []platform.ControlAttestation{{ControlID: "CC6.1", Verdict: platform.AttestPending}}})
	_ = d.Store.PutAuditEngagement(ctx, platform.AuditEngagement{ID: "ab", TenantID: "tB", Framework: "soc2", Status: platform.AuditPlanning,
		Attestations: []platform.ControlAttestation{{ControlID: "CC6.1", Verdict: platform.AttestPending}}})
	attest := d.operatorAuth(d.handleOperatorAttestControl)

	arec := attestAsOperator(t, attest, login.Token, "tA", "aa", `{"control_id":"CC6.1","verdict":"passed","note":"evidence reviewed"}`)
	if arec.Code != http.StatusOK {
		t.Fatalf("attest-on-behalf on assigned client: %d %s", arec.Code, arec.Body.String())
	}
	aud, _ := d.findAuditByID(ctx, "tA", "aa")
	c := aud.Attestations[0]
	if c.Verdict != platform.AttestPassed || c.AttestedBy != "Dana" || c.Capacity != platform.CapacityManaged {
		t.Errorf("attest must record verdict + named auditor + managed capacity, got verdict=%q by=%q cap=%q", c.Verdict, c.AttestedBy, c.Capacity)
	}

	// ISOLATION: dana cannot attest tenant B's control → 403, left pending
	if f := attestAsOperator(t, attest, login.Token, "tB", "ab", `{"control_id":"CC6.1","verdict":"passed"}`); f.Code != http.StatusForbidden {
		t.Fatalf("attest-on-behalf on an UNASSIGNED client must be 403, got %d", f.Code)
	}
	audB, _ := d.findAuditByID(ctx, "tB", "ab")
	if audB.Attestations[0].Verdict != platform.AttestPending {
		t.Errorf("ISOLATION: the unassigned client's control must stay pending, got %q", audB.Attestations[0].Verdict)
	}
}

func attestAsOperator(t *testing.T, h http.HandlerFunc, token, tenant, audit, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/"+tenant+"/audits/"+audit+"/attest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("tenant", tenant)
	req.SetPathValue("id", audit)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func (d Deps) findAuditByID(ctx context.Context, tenantID, id string) (platform.AuditEngagement, bool) {
	es, _ := d.Store.ListAuditEngagements(ctx, tenantID)
	for _, e := range es {
		if e.ID == id {
			return e, true
		}
	}
	return platform.AuditEngagement{}, false
}

func signoffAsOperator(t *testing.T, h http.HandlerFunc, token, tenant, eng, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/"+tenant+"/pentests/"+eng+"/signoff", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("tenant", tenant)
	req.SetPathValue("id", eng)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func publishAsOperator(t *testing.T, h http.HandlerFunc, token, tenant, policy string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/tenants/"+tenant+"/policies/"+policy+"/publish", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	req.SetPathValue("tenant", tenant)
	req.SetPathValue("id", policy)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
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
