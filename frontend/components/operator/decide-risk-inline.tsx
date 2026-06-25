"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { Check } from "lucide-react";
import { operatorDecideRisk } from "@/app/operator/actions";

// DecideRiskInline is the act-on-behalf control on a risk queue item: the operator picks a treatment +
// optional rationale and decides the client's risk without leaving their cross-tenant desk. The Go API
// gates it (must be a practitioner of record for that client) and signs it into the ledger.
export function DecideRiskInline({ tenant, risk }: { tenant: string; risk: string }) {
  const [error, action] = useActionState(operatorDecideRisk, null);
  return (
    <form action={action} className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
      <input type="hidden" name="tenant" value={tenant} />
      <input type="hidden" name="risk" value={risk} />
      <select
        name="treatment"
        defaultValue="mitigate"
        className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-ink"
        aria-label="Treatment"
      >
        <option value="mitigate">Mitigate</option>
        <option value="accept">Accept</option>
        <option value="transfer">Transfer</option>
        <option value="avoid">Avoid</option>
      </select>
      <input
        name="rationale"
        placeholder="Rationale (optional)"
        className="min-w-0 flex-1 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint"
      />
      <Submit />
      {error ? <span className="w-full text-[11px] text-critical">{error}</span> : null}
    </form>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
    >
      <Check className="h-3.5 w-3.5" /> {pending ? "Recording…" : "Decide"}
    </button>
  );
}
