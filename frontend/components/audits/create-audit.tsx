"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Plus, FileCheck2 } from "lucide-react";
import { createAudit } from "@/app/(app)/audits/actions";

const FRAMEWORKS = [
  ["soc2", "SOC 2"],
  ["iso27001", "ISO 27001"],
  ["pci", "PCI-DSS"],
  ["hipaa", "HIPAA"],
  ["nist_csf", "NIST CSF"],
  ["gdpr", "GDPR"],
];

// CreateAudit opens an engagement. The controls to attest are seeded server-side from the tenant's
// real posture for the chosen framework — the auditor then renders each verdict.
export function CreateAudit() {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover"
      >
        <Plus className="h-4 w-4" /> New engagement
      </button>
    );
  }

  return (
    <form action={createAudit} className="card w-full space-y-3 p-4">
      <div className="flex items-center gap-2 text-sm font-semibold">
        <FileCheck2 className="h-4 w-4 text-accent" /> Open an audit engagement
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <label className="text-xs text-muted">
          Framework
          <select name="framework" required defaultValue="soc2" className="mt-1 w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm text-ink">
            {FRAMEWORKS.map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          Type
          <select name="audit_type" defaultValue="type_i" className="mt-1 w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm text-ink">
            <option value="type_i">Type I (point in time)</option>
            <option value="type_ii">Type II (over a period)</option>
          </select>
        </label>
      </div>
      <input name="auditor_name" required placeholder="Auditor name (the independent CPA / firm contact)" className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm" />
      <div className="grid gap-2 sm:grid-cols-2">
        <input name="auditor_firm" placeholder="Audit firm" className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm" />
        <input name="auditor_email" type="email" placeholder="Auditor email" className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm" />
      </div>
      <p className="text-[11px] leading-relaxed text-faint">
        The auditor is an <span className="text-muted">independent licensed firm</span> (a CPA firm for SOC 2)
        that you engage — that independence is what makes the report credible, so it can&apos;t be us. TensorShield
        assembles the controls + evidence here so you&apos;re audit-ready and the engagement is faster &amp; cheaper.
        Don&apos;t have a firm yet? On a managed or MSP plan, your practitioner can help you prepare and recommend
        audit partners.
      </p>
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
    <button type="submit" disabled={pending} className="rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50">
      {pending ? "Opening…" : "Open engagement"}
    </button>
  );
}
