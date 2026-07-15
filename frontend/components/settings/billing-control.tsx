"use client";

import { useState } from "react";
import { Loader2, Sparkles, Check } from "lucide-react";
import { cn } from "@/lib/utils";

// The self-serve purchase control — the difference between a pricing page and a business. Before this
// there was no way for a customer to become paid at all.
//
// Flow: POST /api/billing-checkout (server-side, session-authed) → a real Razorpay order → open
// Razorpay Checkout with the PUBLIC key id. The plan is NOT flipped here: Razorpay's signed webhook
// does that server-side, so a customer closing the tab (or faking a success callback) can never grant
// themselves a plan. On success we poll our own API until the webhook lands.

type Amounts = { base_paise: number; gst_paise: number; total_paise: number; gst_rate: number };
type Order = { order_id: string; key_id: string; amounts: Amounts; descriptor: string; error?: string };

declare global {
  interface Window {
    Razorpay?: new (opts: Record<string, unknown>) => { open: () => void };
  }
}

const rupees = (paise: number) =>
  (paise / 100).toLocaleString("en-IN", { style: "currency", currency: "INR", maximumFractionDigits: 2 });

function loadRazorpay(): Promise<boolean> {
  if (typeof window === "undefined") return Promise.resolve(false);
  if (window.Razorpay) return Promise.resolve(true);
  return new Promise((resolve) => {
    const s = document.createElement("script");
    s.src = "https://checkout.razorpay.com/v1/checkout.js";
    s.onload = () => resolve(true);
    s.onerror = () => resolve(false);
    document.body.appendChild(s);
  });
}

export function BillingControl({ plan, planLabel }: { plan: string; planLabel: string }) {
  const [cycle, setCycle] = useState<"monthly" | "annual">("monthly");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const paid = plan !== "free" && plan !== "";

  async function upgrade() {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/billing-checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: "growth", cycle }),
      });
      const order: Order = await res.json().catch(() => ({}) as Order);
      if (!res.ok) {
        // The platform tells us honestly when payments aren't configured — surface that, don't pretend.
        setMsg(order?.error ?? "Could not start checkout.");
        return;
      }
      if (!(await loadRazorpay())) {
        setMsg("Could not load the payment window. Check your connection and try again.");
        return;
      }
      const rzp = new window.Razorpay!({
        key: order.key_id,
        order_id: order.order_id,
        name: "TensorShield",
        description: order.descriptor,
        theme: { color: "#4F46E5" },
        handler: () => {
          // Payment succeeded in the browser. The PLAN still flips only when Razorpay's signed webhook
          // reaches us — so we wait for that rather than trusting this callback.
          setMsg("Payment received. Activating your plan…");
          setTimeout(() => window.location.reload(), 4000);
        },
        modal: { ondismiss: () => setMsg(null) },
      });
      rzp.open();
    } catch {
      setMsg("Could not start checkout.");
    } finally {
      setBusy(false);
    }
  }

  if (paid) {
    return (
      <div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-surface px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Check className="h-4 w-4 text-success" /> {planLabel}
          </div>
          <p className="mt-1 text-xs text-muted">
            Your AI Security Engineer and AI Pentester are active. Connect your model in the LLM settings below.
          </p>
        </div>
        <a href="mailto:billing@tensorshield.ai" className="shrink-0 text-xs font-medium text-muted hover:text-ink">
          Billing help
        </a>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-border bg-surface px-4 py-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-sm font-semibold text-ink">You&apos;re on Free — scanning only</div>
          <p className="mt-1 max-w-md text-xs leading-relaxed text-muted">
            Upgrade to Core for your AI Security Engineer and AI Pentester across code, cloud and SaaS. You
            connect your own model key, so there&apos;s no markup from us.
          </p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-border p-0.5 text-xs">
          {(["monthly", "annual"] as const).map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setCycle(c)}
              className={cn(
                "rounded-md px-2.5 py-1 font-medium capitalize transition",
                cycle === c ? "bg-accent text-white" : "text-muted hover:text-ink",
              )}
            >
              {c === "annual" ? "Annual · save ~2 months" : "Monthly"}
            </button>
          ))}
        </div>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={upgrade}
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:opacity-90 disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
          Upgrade to Core — {cycle === "monthly" ? `${rupees(799900)}/mo` : `${rupees(7999000)}/yr`} + GST
        </button>
        <span className="text-xs text-muted">UPI · cards · netbanking</span>
      </div>
      {msg && <p className="mt-3 text-xs text-muted">{msg}</p>}
    </div>
  );
}
