"use client";

import { useState, useTransition } from "react";
import { Plus, Loader2, CircleAlert, Trash2 } from "lucide-react";
import { addCustomFramework, deleteCustomFramework } from "./actions";

// Create form for a custom framework — name + a controls textarea ("Name | cwe:CWE-89, soc2:CC6.1").
export function CustomFrameworkForm() {
  const [pending, start] = useTransition();
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  function submit(fd: FormData) {
    setErr(null);
    start(async () => {
      const r = await addCustomFramework(fd);
      if (!r.ok) setErr(r.error ?? "Failed");
      else setOpen(false);
    });
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-xs font-medium text-accent transition hover:border-accent">
        <Plus className="h-3.5 w-3.5" /> New custom framework
      </button>
    );
  }
  return (
    <form action={submit} className="card space-y-3 p-4">
      <input name="name" placeholder="Framework name (e.g. ACME Vendor Security)" required className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm" />
      <input name="description" placeholder="Short description (optional)" className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm" />
      <div>
        <label className="text-xs text-muted">One control per line — <code className="mono">Control name | ref, ref</code> where a ref is <code className="mono">cwe:CWE-89</code>, <code className="mono">rule:secrets</code>, or a built-in control <code className="mono">soc2:CC6.1</code>:</label>
        <textarea name="controls" rows={5} required placeholder={"No SQL injection | cwe:CWE-89\nNo hard-coded secrets | rule:secrets, cwe:CWE-798\nAccess control | soc2:CC6.1, cwe:CWE-862"} className="mono mt-1 w-full rounded-lg border border-border bg-bg px-3 py-2 text-xs" />
      </div>
      {err && <div className="flex items-center gap-2 text-xs text-critical"><CircleAlert className="h-3.5 w-3.5" /> {err}</div>}
      <div className="flex items-center gap-2">
        <button type="submit" disabled={pending} className="inline-flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />} Create
        </button>
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-muted hover:text-ink">Cancel</button>
      </div>
    </form>
  );
}

export function DeleteCustomFramework({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button onClick={() => start(() => deleteCustomFramework(id))} disabled={pending} title="Delete" className="text-faint transition hover:text-critical disabled:opacity-50">
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
    </button>
  );
}
