"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Check, AlertTriangle, Gavel } from "lucide-react";
import type { ControlAttestation } from "@/lib/types";
import { attestControl } from "@/app/(app)/audits/actions";

// AttestControl renders one control + the auditor's HITL verdict form. The verdict is the independent
// auditor's call (passed / exception) — the engine never sets it. attested_by is pre-filled with the
// engagement's auditor so the legal signer is named.
export function AttestControl({ id, c, auditorName }: { id: string; c: ControlAttestation; auditorName: string }) {
  const [open, setOpen] = useState(false);
  const attested = c.verdict === "passed" || c.verdict === "exception";

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border bg-surface px-3 py-2">
      <div className="flex items-center gap-2.5">
        <span className="mono text-xs font-semibold text-ink">{c.control_id}</span>
        {attested ? (
          <span className={`inline-flex items-center gap-1 text-[11px] font-medium ${c.verdict === "passed" ? "text-pulse" : "text-medium"}`}>
            {c.verdict === "passed" ? <Check className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />} {c.verdict}
          </span>
        ) : (
          <span className="text-[11px] text-faint">pending</span>
        )}
        {c.attested_by && <span className="text-[11px] text-faint">· {c.attested_by}</span>}
        <button onClick={() => setOpen((v) => !v)} className="ml-auto inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent">
          <Gavel className="h-3 w-3" /> {attested ? "Re-attest" : "Attest"}
        </button>
      </div>
      {c.note && <p className="text-[11px] text-muted">&ldquo;{c.note}&rdquo;</p>}

      {open && (
        <form action={attestControl} className="space-y-2 border-t border-border pt-2">
          <input type="hidden" name="id" value={id} />
          <input type="hidden" name="control_id" value={c.control_id} />
          <div className="flex flex-wrap items-center gap-2">
            <select name="verdict" required defaultValue="" className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm">
              <option value="" disabled>Verdict…</option>
              <option value="passed">Passed — control operating</option>
              <option value="exception">Exception — gap noted</option>
            </select>
            <input name="attested_by" required defaultValue={auditorName} placeholder="Auditor name" className="flex-1 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm" />
          </div>
          <input name="note" placeholder="Note (optional) — recorded with the attestation" className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm" />
          <Submit />
        </form>
      )}
    </div>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" disabled={pending} className="rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50">
      {pending ? "Recording…" : "Record attestation"}
    </button>
  );
}
