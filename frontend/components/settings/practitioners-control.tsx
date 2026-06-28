"use client";

import Link from "next/link";
import { useState, useTransition } from "react";
import { Loader2, Plus, Trash2, BadgeCheck, AlertTriangle, ArrowUpRight } from "lucide-react";
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

  // Contradiction check: a managed/MSP model needs ≥1 expert of the matching capacity, else HITL acts
  // can't be attributed to the right firm. Best-effort hint from the current roster (the prop refreshes
  // after add/remove via the server action's revalidate).
  const needsCapacity = model === "managed" ? "managed" : model === "msp" ? "msp" : null;
  const contradiction = needsCapacity !== null && !practitioners.some((p) => p.capacity === needsCapacity);

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted">
        Who provides the human-in-the-loop — and the named experts of record. The <strong>capacity</strong> (who employs the
        expert) is stamped on every HITL act, so a risk decision, attestation, or report sign-off is honest about who acted.
      </p>

      {/* service model selector */}
      <div className="grid gap-2 sm:grid-cols-3">
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

      {/* contradiction warning — model says managed/MSP but no matching-capacity expert is on file. */}
      {contradiction && (
        <div className="flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/5 px-3 py-2 text-[11px] text-medium">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            You picked <strong>{MODELS.find((m) => m.value === model)?.label}</strong>, but no{" "}
            {needsCapacity === "managed" ? "managed" : "MSP / partner"}-capacity expert is on file. Add one below so every
            human-in-the-loop act is attributed to the right person and firm.
          </span>
        </div>
      )}

      {/* roster */}
      {practitioners.length > 0 && (
        <ul className="space-y-1.5">
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
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
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
      {err && <p className="text-[11px] text-critical">{err}</p>}

      {/* roster ↔ operator-login connection + the read-only team view (§18.5). */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-[11px] text-faint">
        <span>
          An expert with an email signs into the cross-tenant{" "}
          <Link href="/operator/login" className="font-medium text-muted hover:text-ink hover:underline">operator console</Link>{" "}
          to work this client&apos;s queue.
        </span>
        <Link href="/security-team" className="inline-flex items-center gap-1 font-medium text-accent hover:underline">
          View your security team <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>
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
