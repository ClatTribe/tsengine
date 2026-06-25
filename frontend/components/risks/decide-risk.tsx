"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Gavel, Check } from "lucide-react";
import { decideRisk } from "@/app/(app)/risks/actions";

const TREATMENTS = [
  { value: "accept", label: "Accept", hint: "Own the residual risk as-is" },
  { value: "mitigate", label: "Mitigate", hint: "Reduce with a control / fix" },
  { value: "transfer", label: "Transfer", hint: "Shift to a third party (insurance/vendor)" },
  { value: "avoid", label: "Avoid", hint: "Remove the exposed function" },
];

// DecideRisk is the human-in-the-loop control. A risk decision is a judgment call the agent cannot
// make — so this is a person, by name, choosing a treatment with a rationale. The decision is signed
// into the ledger server-side.
export function DecideRisk({ id, decided }: { id: string; decided: boolean }) {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
      >
        <Gavel className="h-3.5 w-3.5" /> {decided ? "Re-decide" : "Decide"}
      </button>
    );
  }

  return (
    <form action={decideRisk} className="mt-2 w-full space-y-2 rounded-xl border border-accent/30 bg-accent-soft/20 p-3">
      <input type="hidden" name="id" value={id} />
      <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">Treatment decision</div>
      <select name="treatment" required defaultValue="" className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm">
        <option value="" disabled>
          Choose a treatment…
        </option>
        {TREATMENTS.map((t) => (
          <option key={t.value} value={t.value}>
            {t.label} — {t.hint}
          </option>
        ))}
      </select>
      <input
        name="owner"
        placeholder="Accountable owner (name) — defaults to you"
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <textarea
        name="rationale"
        rows={2}
        placeholder="Rationale (why this treatment) — recorded into the signed ledger"
        className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
      />
      <div className="flex items-center gap-2">
        <Submit />
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-muted transition hover:text-ink">
          Cancel
        </button>
      </div>
    </form>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
    >
      <Check className="h-3.5 w-3.5" /> {pending ? "Recording…" : "Record decision"}
    </button>
  );
}
