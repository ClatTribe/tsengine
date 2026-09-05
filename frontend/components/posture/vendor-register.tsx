"use client";

import { useState } from "react";
import { useFormStatus } from "react-dom";
import { Building2, Plus, Trash2, Check } from "lucide-react";
import type { VendorsResponse, Vendor } from "@/lib/types";
import { saveVendor, removeVendor } from "@/app/(app)/posture/actions";

// The vendor REGISTER: who you buy from, what each of them can touch, who is accountable, and when
// somebody last looked. Distinct from the findings below it, which say what is WRONG — a list
// derived from findings names the suppliers that failed a check and omits every well-managed one,
// which is not an inventory and is not what an auditor asks for.
export function VendorRegister({ data }: { data: VendorsResponse }) {
  const [adding, setAdding] = useState(false);
  const s = data.summary;

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted">
          <Building2 className="h-3.5 w-3.5" /> Vendor register
        </h2>
        <button
          onClick={() => setAdding((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
        >
          <Plus className="h-3.5 w-3.5" /> Add a vendor
        </button>
      </div>

      <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <Stat n={s.total} label="On the register" />
        <Stat n={s.subprocessors} label="Sub-processors" />
        <Stat n={s.sensitive_data} label="Sensitive data" cls="text-high" />
        {/* Never-reviewed and unowned are shown as their own numbers rather than folded into a
            "compliance score": one figure would blend "we hold their SOC 2 report" with "nobody has
            looked at this since 2024", and it would RISE as a customer recorded fewer vendors. */}
        <Stat n={s.never_reviewed} label="Never reviewed" cls="text-accent" />
        <Stat n={s.unowned} label="Unowned" cls="text-accent" />
      </div>

      {/* The server's own sentence. It carries the refusal that an empty register is not a clean one. */}
      <p className="text-sm text-muted">{s.detail}</p>

      {adding && <VendorForm onDone={() => setAdding(false)} />}

      {data.vendors.length > 0 && (
        <ul className="space-y-2">
          {data.vendors.map((v) => (
            <VendorRow key={v.id} v={v} />
          ))}
        </ul>
      )}
    </section>
  );
}

function VendorRow({ v }: { v: Vendor }) {
  const [busy, setBusy] = useState(false);
  return (
    <li className="card flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-ink">{v.name}</span>
          {v.subprocessor && <Chip>sub-processor</Chip>}
          {v.data_access === "sensitive" && <Chip tone="high">sensitive data</Chip>}
          {v.data_access === "pii" && <Chip>personal data</Chip>}
          {v.handles_card_data && <Chip>card data</Chip>}
          {(v.certifications ?? []).map((c) => (
            <Chip key={c} tone="ok">
              {c}
            </Chip>
          ))}
          {v.source === "ingest" && <Chip>from an inventory feed</Chip>}
        </div>
        <div className="mt-1 text-xs text-faint">
          {/* Unowned and never-reviewed are stated in words, not left as a blank cell a reader fills
              in optimistically. */}
          {v.owner ? `Owned by ${v.owner}` : "No named owner"}
          {" · "}
          {v.last_assessed ? `reviewed ${v.last_assessed}` : "never reviewed"}
          {v.criticality ? ` · ${v.criticality} criticality` : ""}
        </div>
      </div>
      <button
        onClick={() => {
          setBusy(true);
          removeVendor(v.id).finally(() => setBusy(false));
        }}
        disabled={busy}
        aria-label={`Remove ${v.name}`}
        className="rounded-lg border border-border p-1.5 text-muted transition hover:border-high/40 hover:text-high disabled:opacity-50"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </li>
  );
}

function VendorForm({ onDone }: { onDone: () => void }) {
  return (
    <form
      action={async (fd) => {
        await saveVendor(fd);
        onDone();
      }}
      className="card space-y-2 p-4"
    >
      <div className="grid gap-2 sm:grid-cols-2">
        <input name="name" required placeholder="Vendor name" className={field} />
        <input name="owner" placeholder="Accountable owner (leave blank if nobody owns it yet)" className={field} />
        <input name="category" placeholder="Category — e.g. analytics, payments" className={field} />
        <select name="data_access" defaultValue="" className={field}>
          <option value="">What can they touch…</option>
          <option value="none">No access to our data</option>
          <option value="metadata">Operational metadata</option>
          <option value="pii">Personal data</option>
          <option value="sensitive">Sensitive — PHI, card data, secrets</option>
        </select>
        <input name="certifications" placeholder="Certifications, comma separated — SOC2, ISO27001" className={field} />
        <select name="criticality" defaultValue="" className={field}>
          <option value="">Business criticality…</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <input name="last_assessed" type="date" aria-label="Last reviewed" className={field} />
      </div>
      <div className="flex flex-wrap gap-4 text-sm text-muted">
        <label className="flex items-center gap-1.5">
          <input type="checkbox" name="subprocessor" className="h-4 w-4 rounded border-border accent-accent" />
          Sub-processor
        </label>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" name="has_dpa" className="h-4 w-4 rounded border-border accent-accent" />
          DPA signed
        </label>
        <label className="flex items-center gap-1.5">
          <input type="checkbox" name="handles_card_data" className="h-4 w-4 rounded border-border accent-accent" />
          Handles card data
        </label>
      </div>
      <div className="flex items-center gap-2">
        <Submit />
        <button type="button" onClick={onDone} className="text-xs text-muted transition hover:text-ink">
          Cancel
        </button>
      </div>
      {/* Every field here is DECLARED. Nothing about a vendor's name or category says whether they
          hold personal data or whether a DPA was signed, so none of it is guessed. */}
      <p className="text-[11px] text-muted">
        These are stated facts, not inferences — the assessment only ever acts on what you record
        here, so a blank field is treated as unknown rather than as fine.
      </p>
    </form>
  );
}

const field =
  "rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm outline-none transition focus:border-accent";

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
    >
      <Check className="h-3.5 w-3.5" /> {pending ? "Saving…" : "Save vendor"}
    </button>
  );
}

function Chip({ children, tone = "muted" }: { children: React.ReactNode; tone?: "muted" | "high" | "ok" }) {
  const cls =
    tone === "high" ? "border-high/40 text-high" : tone === "ok" ? "border-pulse/40 text-pulse" : "border-border text-muted";
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] ${cls}`}>{children}</span>;
}

function Stat({ n, label, cls = "text-ink" }: { n: number; label: string; cls?: string }) {
  return (
    <div>
      <div className={`text-xl font-semibold ${cls}`}>{n}</div>
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}
