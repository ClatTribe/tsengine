package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// auditorders.go is the PER-APPLICATION SKU — the commercial half of the audit desk.
//
// internal/auditreview is the WORK: a named reviewer decides each finding and a certificate issues
// when nothing stands in the way. This file records the MONEY, and the one commercial term every
// tender in this market sets: 100% on acceptance of the final report, no advance. So an order is
// created at a price, becomes CERTIFIED when the desk issues the certificate for its target, and
// becomes ACCEPTED only when the buyer's named human accepts it — the payment event. The amount due
// is computed from the status (AuditOrder.AmountDueINR) rather than stored, so a page an operator
// invoices from cannot show money owed on work the buyer has not accepted.
//
// Three doors. Creating and accepting are tenant acts (the firm quotes, the buyer accepts).
// Invoicing is the OPERATOR's act (platform token), because the invoice is the seller's document.

type auditOrderView struct {
	platform.AuditOrder
	// AmountDueINR is what is owed NOW. Zero until accepted — the no-advance term, stated on every row.
	AmountDueINR int `json:"amount_due_inr"`
}

func orderView(o platform.AuditOrder) auditOrderView {
	return auditOrderView{AuditOrder: o, AmountDueINR: o.AmountDueINR()}
}

// handleListAuditOrders lists the tenant's per-application orders, oldest first.
func (d Deps) handleListAuditOrders(w http.ResponseWriter, r *http.Request, tenantID string) {
	orders, err := d.Store.ListAuditOrders(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	out := make([]auditOrderView, 0, len(orders))
	due := 0
	for _, o := range orders {
		v := orderView(o)
		due += v.AmountDueINR
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"orders": out, "list_price_inr": platform.AuditListPriceINR, "amount_due_inr": due,
	})
}

// handleCreateAuditOrder opens an order for one application at the list price, or at the agreed
// price the caller records. The target is the application exactly as the audit desk names it, so
// the certificate the desk later issues can find the order.
func (d Deps) handleCreateAuditOrder(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Target   string `json:"target"`
		PriceINR int    `json:"price_inr"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	target := strings.TrimSpace(body.Target)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a target application is required"))
		return
	}
	if body.PriceINR < 0 {
		writeJSON(w, http.StatusBadRequest, errBody("price_inr cannot be negative"))
		return
	}
	// One OPEN order per application. A second order for the same target while the first is still
	// open is almost always a double-click, and two open orders for one certificate would bill the
	// same work twice.
	existing, err := d.Store.ListAuditOrders(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	for _, o := range existing {
		if strings.EqualFold(o.Target, target) && o.Status == platform.AuditOrderOpen {
			writeJSON(w, http.StatusConflict, errBody("an open order already exists for "+target+" ("+o.ID+")"))
			return
		}
	}
	price := body.PriceINR
	if price == 0 {
		price = platform.AuditListPriceINR
	}
	now := time.Now().UTC()
	o := platform.AuditOrder{
		TenantID: tenantID, ID: d.newID("ord"), Target: target, PriceINR: price,
		Status: platform.AuditOrderOpen, Note: strings.TrimSpace(body.Note),
		CreatedAt: now, CreatedBy: d.actingEmail(r),
	}
	if err := d.Store.PutAuditOrder(r.Context(), o); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit order opened", "audit_order",
			map[string]any{"tenant_id": tenantID, "order_id": o.ID, "target": o.Target, "price_inr": o.PriceINR, "note": o.Note, "by": o.CreatedBy},
			"per-application audit ordered; nothing is due until the certificate is accepted")
	}
	writeJSON(w, http.StatusCreated, orderView(o))
}

// handleAcceptAuditOrder records the BUYER's acceptance of the certificate — the payment event.
// Refused unless a certificate has been issued for the order: accepting work that has not been
// delivered would make money due on nothing, which is the advance the terms forbid.
func (d Deps) handleAcceptAuditOrder(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		By string `json:"by"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	o, ok := d.findAuditOrder(r.Context(), tenantID, r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("order not found"))
		return
	}
	switch o.Status {
	case platform.AuditOrderCertified:
	case platform.AuditOrderAccepted, platform.AuditOrderInvoiced:
		writeJSON(w, http.StatusConflict, errBody("this order was already accepted on "+o.AcceptedAt.UTC().Format("2 January 2006")+" by "+o.AcceptedBy))
		return
	default:
		writeJSON(w, http.StatusConflict, errBody("no certificate has been issued for "+o.Target+" yet — acceptance is of the certificate, and there is nothing to accept"))
		return
	}
	by := strings.TrimSpace(body.By)
	if by == "" {
		by = d.actingEmail(r)
	}
	if by == "" {
		writeJSON(w, http.StatusBadRequest, errBody("acceptance must name the person accepting — it is the payment event"))
		return
	}
	o.Status, o.AcceptedBy, o.AcceptedAt = platform.AuditOrderAccepted, by, time.Now().UTC()
	if err := d.Store.PutAuditOrder(r.Context(), o); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit certificate accepted", "audit_order",
			map[string]any{"tenant_id": tenantID, "order_id": o.ID, "target": o.Target, "certificate_id": o.CertificateID,
				"accepted_by": by, "amount_due_inr": o.AmountDueINR()},
			"buyer accepted the Safe-to-Host certificate — the per-application fee is now due")
	}
	writeJSON(w, http.StatusOK, orderView(o))
}

// handleInvoiceAuditOrder is the OPERATOR recording that the invoice was raised. Refused unless the
// buyer has accepted: invoicing before acceptance is the advance the terms exclude.
func (d Deps) handleInvoiceAuditOrder(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.PathValue("tenant"))
	var body struct {
		InvoiceRef string `json:"invoice_ref"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	ref := strings.TrimSpace(body.InvoiceRef)
	if ref == "" {
		writeJSON(w, http.StatusBadRequest, errBody("an invoice_ref is required"))
		return
	}
	o, ok := d.findAuditOrder(r.Context(), tenantID, r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("order not found"))
		return
	}
	if o.Status != platform.AuditOrderAccepted {
		writeJSON(w, http.StatusConflict, errBody("the order is "+string(o.Status)+", not accepted — nothing is due until the buyer accepts the certificate"))
		return
	}
	o.Status, o.InvoiceRef, o.InvoicedAt = platform.AuditOrderInvoiced, ref, time.Now().UTC()
	if err := d.Store.PutAuditOrder(r.Context(), o); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		d.Recorder.Record("audit order invoiced", "audit_order",
			map[string]any{"tenant_id": tenantID, "order_id": o.ID, "target": o.Target, "invoice_ref": ref, "amount_inr": o.PriceINR},
			"operator raised the invoice for an accepted certificate")
	}
	writeJSON(w, http.StatusOK, orderView(o))
}

func (d Deps) findAuditOrder(ctx context.Context, tenantID, id string) (platform.AuditOrder, bool) {
	orders, err := d.Store.ListAuditOrders(ctx, tenantID)
	if err != nil {
		return platform.AuditOrder{}, false
	}
	for _, o := range orders {
		if o.ID == id {
			return o, true
		}
	}
	return platform.AuditOrder{}, false
}

// markAuditOrdersCertified advances every OPEN order for the target to certified when the desk
// issues its certificate. Called from both certificate doors so the order cannot depend on which
// button was pressed. Best-effort: a store error here must never fail the issuance that already
// happened — the certificate is the customer's; the order is our bookkeeping.
func (d Deps) markAuditOrdersCertified(ctx context.Context, tenantID, target, certificateID string, now time.Time) {
	orders, err := d.Store.ListAuditOrders(ctx, tenantID)
	if err != nil {
		return
	}
	for _, o := range orders {
		if o.Status != platform.AuditOrderOpen || !strings.EqualFold(strings.TrimSpace(o.Target), strings.TrimSpace(target)) {
			continue
		}
		o.Status, o.CertificateID, o.CertifiedAt = platform.AuditOrderCertified, certificateID, now.UTC()
		if err := d.Store.PutAuditOrder(ctx, o); err != nil {
			continue
		}
		if d.Recorder != nil {
			d.Recorder.Record("audit order certified", "audit_order",
				map[string]any{"tenant_id": tenantID, "order_id": o.ID, "target": o.Target, "certificate_id": certificateID},
				"certificate issued for the ordered application; awaiting the buyer's acceptance")
		}
	}
}
