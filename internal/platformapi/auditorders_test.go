package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func postOrder(d Deps, tok, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	d.handleCreateAuditOrder(rec, arReq(http.MethodPost, "/v1/audit-orders", body, tok), arTenant)
	return rec
}

func acceptOrder(d Deps, tok, id, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := arReq(http.MethodPost, "/v1/audit-orders/"+id+"/accept", body, tok)
	req.SetPathValue("id", id)
	d.handleAcceptAuditOrder(rec, req, arTenant)
	return rec
}

func listOrders(t *testing.T, d Deps, tok string) (orders []auditOrderView, due int) {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handleListAuditOrders(rec, arReq(http.MethodGet, "/v1/audit-orders", "", tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Orders       []auditOrderView `json:"orders"`
		AmountDueINR int              `json:"amount_due_inr"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Orders, body.AmountDueINR
}

// THE COMMERCIAL TERM. Every tender in this market pays 100% on acceptance and never in advance. The
// order machine encodes it: nothing is due while open, nothing is due while merely certified, the
// full price is due once the buyer's named human accepts.
func TestAuditOrder_NothingIsDueBeforeTheBuyerAccepts(t *testing.T) {
	d, tok := certifiableAudit(t)

	rec := postOrder(d, tok, `{"target":"`+arTarget+`","note":"GeM bid 4471"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var o auditOrderView
	_ = json.Unmarshal(rec.Body.Bytes(), &o)
	if o.PriceINR != platform.AuditListPriceINR || o.Status != platform.AuditOrderOpen || o.AmountDueINR != 0 || o.CreatedBy != "ada@acme-audit.example" {
		t.Fatalf("a fresh order is at list price, open, nothing due, attributed: %+v", o)
	}

	// Accepting before any certificate exists is refused — there is nothing to accept.
	if rec := acceptOrder(d, tok, o.ID, `{}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no certificate") {
		t.Fatalf("accept before certificate: %d %s", rec.Code, rec.Body.String())
	}

	// The desk issues the certificate → the order becomes certified, still nothing due.
	rec = httptest.NewRecorder()
	d.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate", `{"target":"`+arTarget+`"}`, tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificate: %d %s", rec.Code, rec.Body.String())
	}
	orders, due := listOrders(t, d, tok)
	if len(orders) != 1 || orders[0].Status != platform.AuditOrderCertified || orders[0].CertificateID == "" || due != 0 {
		t.Fatalf("certified, with the certificate id, and STILL nothing due: %+v due=%d", orders, due)
	}

	// The buyer accepts → the full price is due, attributed to a named person.
	rec = acceptOrder(d, tok, o.ID, `{"by":"S. Rao, ORGI"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &o)
	if o.Status != platform.AuditOrderAccepted || o.AcceptedBy != "S. Rao, ORGI" || o.AmountDueINR != platform.AuditListPriceINR {
		t.Fatalf("accepted: %+v", o)
	}
	if _, due := listOrders(t, d, tok); due != platform.AuditListPriceINR {
		t.Errorf("the roll-up owes the price now: %d", due)
	}
	// Accepting twice is refused, naming the first acceptance.
	if rec := acceptOrder(d, tok, o.ID, `{"by":"someone else"}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "S. Rao") {
		t.Errorf("double acceptance: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuditOrder_InvoiceIsTheOperatorsActAndNeedsAcceptance(t *testing.T) {
	d, tok := certifiableAudit(t)
	rec := postOrder(d, tok, `{"target":"`+arTarget+`","price_inr":42000}`)
	var o auditOrderView
	_ = json.Unmarshal(rec.Body.Bytes(), &o)
	if o.PriceINR != 42000 {
		t.Fatalf("an agreed price replaces the list price: %+v", o)
	}
	invoice := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tenants/"+arTenant+"/audit-orders/"+o.ID+"/invoice", strings.NewReader(body))
		req.SetPathValue("tenant", arTenant)
		req.SetPathValue("id", o.ID)
		d.handleInvoiceAuditOrder(rec, req)
		return rec
	}
	if rec := invoice(`{"invoice_ref":"INV-9"}`); rec.Code != http.StatusConflict {
		t.Fatalf("invoicing an open order is the advance the terms forbid: %d %s", rec.Code, rec.Body.String())
	}
	// certify + accept
	rec = httptest.NewRecorder()
	d.handleAuditCertificate(rec, arReq(http.MethodPost, "/v1/audit-review/certificate", `{"target":"`+arTarget+`"}`, tok), arTenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("certificate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := acceptOrder(d, tok, o.ID, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("accept (named from the session): %d %s", rec.Code, rec.Body.String())
	}
	if rec := invoice(`{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an invoice needs a reference: %d", rec.Code)
	}
	rec = invoice(`{"invoice_ref":"INV-9"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoice: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &o)
	if o.Status != platform.AuditOrderInvoiced || o.InvoiceRef != "INV-9" || o.AmountDueINR != 42000 {
		t.Errorf("invoiced: %+v", o)
	}
}

func TestAuditOrder_Refusals(t *testing.T) {
	d, tok := certifiableAudit(t)
	if rec := postOrder(d, tok, `{"target":"  "}`); rec.Code != http.StatusBadRequest {
		t.Errorf("no target: %d", rec.Code)
	}
	if rec := postOrder(d, tok, `{"target":"`+arTarget+`","price_inr":-1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("negative price: %d", rec.Code)
	}
	if rec := postOrder(d, tok, `{"target":"`+arTarget+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("first order: %d", rec.Code)
	}
	if rec := postOrder(d, tok, `{"target":"`+strings.ToUpper(arTarget)+`"}`); rec.Code != http.StatusConflict {
		t.Errorf("a second OPEN order for the same application (any case) is a double-click, not a sale: %d %s", rec.Code, rec.Body.String())
	}
	if rec := acceptOrder(d, tok, "nope", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown order: %d", rec.Code)
	}
	// The certificate document door marks the order too — the order cannot depend on which button.
	d2, tok2 := certifiableAudit(t)
	rec := postOrder(d2, tok2, `{"target":"`+arTarget+`"}`)
	var o auditOrderView
	_ = json.Unmarshal(rec.Body.Bytes(), &o)
	if rec := getDoc(d2, tok2, "&format=json"); rec.Code != http.StatusOK {
		t.Fatalf("document: %d %s", rec.Code, rec.Body.String())
	}
	orders, _ := listOrders(t, d2, tok2)
	if len(orders) != 1 || orders[0].Status != platform.AuditOrderCertified {
		t.Errorf("the GET document door must certify the order as the POST does: %+v", orders)
	}
	// And a store-level check that the tenant is what scopes it.
	other, _ := d.Store.ListAuditOrders(context.Background(), "someone-else")
	if len(other) != 0 {
		t.Error("orders leaked across tenants")
	}
}

// The per-application plan: the asset cap IS the purchased count, read through EntitlementsFor.
func TestSetTenantPlan_AuditTierCapsTargetsAtApplicationsPurchased(t *testing.T) {
	h, st := setup(t)
	rec := do(h, http.MethodPost, "/v1/tenants/t1/plan", "", `{"plan":"audit","audit_applications":3,"note":"GeM bid 4471"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	got, _ := st.GetTenant(context.Background(), "t1")
	if got.Plan != platform.PlanAudit || got.AuditApplications != 3 {
		t.Fatalf("stored: plan=%q applications=%d", got.Plan, got.AuditApplications)
	}
	lim := platform.EntitlementsFor(got)
	if lim.MaxAssets != 3 || !lim.AIEnabled || !lim.AutonomousPentest || lim.ContinuousMonitoring {
		t.Errorf("audit entitlements: %+v", lim)
	}
	// Zero purchased → zero targets. Never a friendly default.
	rec = do(h, http.MethodPost, "/v1/tenants/t1/plan", "", `{"plan":"audit"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-set: %d %s", rec.Code, rec.Body)
	}
	got, _ = st.GetTenant(context.Background(), "t1")
	if platform.EntitlementsFor(got).MaxAssets != 0 {
		t.Errorf("an audit plan with nothing purchased allows no targets, got %d", platform.EntitlementsFor(got).MaxAssets)
	}
	if !strings.Contains(rec.Body.String(), `"max_assets":0`) {
		t.Errorf("the response reports the tenant's real cap: %s", rec.Body.String())
	}
}
