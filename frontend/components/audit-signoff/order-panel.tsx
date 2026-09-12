"use client";

import { useState } from "react";
import { IndianRupee, Loader2, Receipt } from "lucide-react";
import type { AuditOrder } from "@/lib/types";
import { createAuditOrder, acceptAuditOrder } from "@/app/(app)/audit-signoff/actions";

// The per-application SKU on the desk: one application, one price, paid on acceptance of its
// certificate. The panel states the amount DUE NOW on every render, and that figure is the server's
// (amount_due_inr, computed from the status), never derived here — because the whole commercial term
// is that nothing is owed before the buyer accepts, and a page that multiplied price by "done" would
// invoice work the buyer has not accepted.
function inr(n: number): string {
  return "₹" + n.toLocaleString("en-IN");
}

const STATUS: Record<AuditOrder["status"], string> = {
  open: "Ordered — audit in progress. Nothing is due.",
  certified: "Certificate issued — awaiting the buyer's acceptance. Nothing is due yet.",
  accepted: "Accepted by the buyer — the fee is now due.",
  invoiced: "Invoiced.",
};

export function OrderPanel({ target, order, listPriceInr }: { target: string; order: AuditOrder | null; listPriceInr: number }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [acceptedBy, setAcceptedBy] = useState("");

  async function create() {
    setBusy(true);
    setErr("");
    const res = await createAuditOrder(target);
    setBusy(false);
    if (!res.ok) setErr(res.error ?? "Could not open the order.");
  }
  async function accept() {
    if (!order) return;
    setBusy(true);
    setErr("");
    const res = await acceptAuditOrder(order.id, acceptedBy.trim());
    setBusy(false);
    if (!res.ok) setErr(res.error ?? "Could not record the acceptance.");
  }

  return (
    <section className="card space-y-3 px-5 py-4">
      <div className="flex items-center gap-2 text-sm font-medium text-ink">
        <Receipt className="h-4 w-4 text-accent" /> Per-application order
      </div>

      {!order ? (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm text-muted">
            No order for this application. The per-application audit is {inr(listPriceInr)} + GST, invoiced only
            when the buyer accepts the certificate — no advance.
          </p>
          <button
            onClick={create}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-ink transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <IndianRupee className="h-3.5 w-3.5" />}
            Open order at {inr(listPriceInr)}
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-sm">
            <span className="text-ink">{STATUS[order.status]}</span>
            <span className="mono text-[11px] text-faint">{order.id}</span>
            {order.note && <span className="text-xs text-muted">{order.note}</span>}
          </div>
          {/* The server's figure, stated on every row. Zero until accepted. */}
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
            <span className="text-muted">
              Price <span className="text-ink">{inr(order.price_inr)}</span> + GST
            </span>
            <span className="text-muted">
              Due now <span className={order.amount_due_inr > 0 ? "font-semibold text-ink" : "text-ink"}>{inr(order.amount_due_inr)}</span>
            </span>
            {order.certificate_id && <span className="mono text-[11px] text-faint">cert {order.certificate_id}</span>}
            {order.accepted_by && <span className="text-xs text-muted">accepted by {order.accepted_by}</span>}
            {order.invoice_ref && <span className="text-xs text-muted">invoice {order.invoice_ref}</span>}
          </div>
          {order.status === "certified" && (
            <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
              <input
                value={acceptedBy}
                onChange={(e) => setAcceptedBy(e.target.value)}
                placeholder="Accepted by (name, organisation)"
                className="w-64 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
              />
              <button
                onClick={accept}
                disabled={busy || !acceptedBy.trim()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Record buyer&rsquo;s acceptance
              </button>
              <span className="text-[11px] text-muted">This is the payment event: the fee becomes due on acceptance.</span>
            </div>
          )}
        </div>
      )}
      {err && <p className="text-xs text-high">{err}</p>}
    </section>
  );
}
