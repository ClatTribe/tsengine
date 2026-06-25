"use client";

import { useState, useTransition } from "react";
import { UserCog, Loader2, Plus, Trash2, BadgeCheck } from "lucide-react";
import { setServiceModel, addPractitioner, deletePractitioner } from "@/app/(app)/settings/actions";
import type { Practitioner } from "@/lib/types";

// Who provides the human-in-the-loop for this tenant — the difference between the two product models.
// self_serve = the tenant's own team; msp = a partner firm's expert; managed = our hired expert.
const MODELS: { value: string; label: string; hint: string }[] = [
  { value: "self_serve", label: "Self-serve", hint: "Your own team makes the judgment calls" },
  { value: "msp", label: "MSP / partner", hint: "A partner firm's expert runs the human-in-the-loop" },
  { value: "managed", label: "Managed (we run it)", hint: "We provide the expert, acting on your behalf" },
];
const CAPACITY: Record<string, string> = { internal: "Internal", msp: "MSP / partner", managed: "Managed (us)" };
const CAP_TONE: Record<string, string> = { internal: "text-muted bg-surface-2", msp: "text-accent bg-accent-soft", managed: "text-pulse bg-pulse-soft" };

export function PractitionersControl({ serviceModel, practitioners }: { serviceModel: string; practitioners: Practitioner[] }) {
  const [model, setModel] = useState(serviceModel || "self_serve");
  const [name, setName] = useState("");
  const [firm, setFirm] = useState("");
  const [credential, setCredential] = useState("");
  const [capacity, setCapacity] = useState("managed");
  const [email, setEmail] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function pickModel(m: string) {
    setModel(m);
    start(() => setServiceModel(m));
  }

  function add() {
    setErr("");
    if (!name.trim()) return setErr("Name is required");
    start(async () => {
      try {
        await addPractitioner({ name: name.trim(), firm: firm.trim(), credential: credential.trim(), capacity, email: email.trim() });
        setName("");
        setFirm("");
        setCredential("");
        setEmail("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to add");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <UserCog className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Service model &amp; practitioners</div>
          <div className="text-xs text-muted">Who provides the human-in-the-loop — and the named experts of record</div>
        </div>
      </div>

      {/* service model selector */}
      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        {MODELS.map((m) => (
          <button
            key={m.value}
            onClick={() => pickModel(m.value)}
            disabled={pending}
            className={`rounded-lg border px-3 py-2 text-left transition disabled:opacity-60 ${
              model === m.value ? "border-accent bg-accent-soft/40" : "border-border bg-surface hover:border-border-strong"
            }`}
          >
            <div className="text-xs font-semibold text-ink">{m.label}</div>
            <div className="mt-0.5 text-[11px] leading-snug text-muted">{m.hint}</div>
          </button>
        ))}
      </div>

      {/* roster */}
      {practitioners.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {practitioners.map((p) => (
            <li key={p.id} className="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-2.5 py-2 text-xs">
              <BadgeCheck className="h-3.5 w-3.5 shrink-0 text-accent" />
              <div className="min-w-0 flex-1">
                <span className="font-medium text-ink">{p.name}</span>
                {p.credential && <span className="ml-1.5 text-[11px] text-faint">· {p.credential}</span>}
                <div className="text-[11px] text-muted">{p.firm || "—"}{p.email ? ` · ${p.email}` : ""}</div>
              </div>
              <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${CAP_TONE[p.capacity] ?? "text-muted bg-surface-2"}`}>
                {CAPACITY[p.capacity] ?? p.capacity}
              </span>
              <DeleteBtn id={p.id} />
            </li>
          ))}
        </ul>
      )}

      {/* add */}
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <input value={firm} onChange={(e) => setFirm(e.target.value)} placeholder="Firm" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <input value={credential} onChange={(e) => setCredential(e.target.value)} placeholder="Credential (CPA, OSCP…)" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <select value={capacity} onChange={(e) => setCapacity(e.target.value)} className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink">
          <option value="internal">Internal</option>
          <option value="msp">MSP / partner</option>
          <option value="managed">Managed (us)</option>
        </select>
        <button onClick={add} disabled={pending} className="inline-flex items-center justify-center gap-1 rounded-md bg-accent px-2.5 py-1.5 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50">
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />} Add expert
        </button>
      </div>
      <p className="mt-1.5 text-[11px] text-faint">The capacity (who employs the expert) is recorded on every human-in-the-loop act — so a risk decision, attestation, or report sign-off is honest about who acted and in what capacity.</p>
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}

function DeleteBtn({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button onClick={() => start(() => deletePractitioner(id))} disabled={pending} title="Remove practitioner" className="shrink-0 text-faint transition hover:text-critical disabled:opacity-50">
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
    </button>
  );
}
