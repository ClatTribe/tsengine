"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { Check } from "lucide-react";
import { operatorAttestControl } from "@/app/operator/actions";

// AttestControlInline is the act-on-behalf control on an audit queue item: the operator (acting as the
// named independent auditor) records a passed/exception verdict on one pending control, from the desk.
// Roster-gated + ledger-signed server-side. controls is the list of control ids still awaiting a verdict.
export function AttestControlInline({ tenant, audit, controls }: { tenant: string; audit: string; controls: string[] }) {
  const [error, action] = useActionState(operatorAttestControl, null);
  if (controls.length === 0) return null;
  return (
    <form action={action} className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
      <input type="hidden" name="tenant" value={tenant} />
      <input type="hidden" name="audit" value={audit} />
      <select name="control_id" className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-ink" aria-label="Control">
        {controls.map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
      <select name="verdict" defaultValue="passed" className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs text-ink" aria-label="Verdict">
        <option value="passed">Passed</option>
        <option value="exception">Exception</option>
      </select>
      <input
        name="note"
        placeholder="Note (optional)"
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
      <Check className="h-3.5 w-3.5" /> {pending ? "Recording…" : "Attest"}
    </button>
  );
}
