"use client";

import { useState, useTransition } from "react";
import { Contact as ContactIcon, Loader2, Plus, Trash2, Mail, Phone } from "lucide-react";
import { addContact, deleteContact } from "@/app/(app)/settings/actions";
import type { Contact } from "@/lib/types";

// On-call escalation roster (the contractual "escalation matrix with contact number"). Ordered list
// of who to reach; the phone number is stored for the matrix, but live SMS/voice paging is gated.
export function ContactsControl({ contacts }: { contacts: Contact[] }) {
  const [name, setName] = useState("");
  const [role, setRole] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function add() {
    setErr("");
    if (!name.trim()) return setErr("Name is required");
    if (!email.trim() && !phone.trim()) return setErr("Add an email or a phone number");
    start(async () => {
      try {
        await addContact({ name: name.trim(), role: role.trim(), email: email.trim(), phone: phone.trim(), order: contacts.length + 1 });
        setName("");
        setRole("");
        setEmail("");
        setPhone("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to add");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <ContactIcon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Escalation contacts</div>
          <div className="text-xs text-muted">Who the on-call matrix reaches, in order — names &amp; numbers</div>
        </div>
      </div>

      {contacts.length > 0 && (
        <ol className="mt-3 space-y-1.5">
          {contacts.map((c, i) => (
            <li key={c.id} className="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-2.5 py-2 text-xs">
              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-surface-2 text-[10px] font-semibold text-muted">{i + 1}</span>
              <div className="min-w-0 flex-1">
                <span className="font-medium text-ink">{c.name}</span>
                {c.role && <span className="ml-1.5 text-[11px] text-faint">· {c.role}</span>}
                <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted">
                  {c.email && <span className="inline-flex items-center gap-1"><Mail className="h-2.5 w-2.5" />{c.email}</span>}
                  {c.phone && <span className="inline-flex items-center gap-1"><Phone className="h-2.5 w-2.5" />{c.phone}</span>}
                </div>
              </div>
              <DeleteBtn id={c.id} />
            </li>
          ))}
        </ol>
      )}

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <input value={role} onChange={(e) => setRole(e.target.value)} placeholder="Role (e.g. On-call)" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
        <div className="flex gap-2">
          <input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="Phone" className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint" />
          <button onClick={add} disabled={pending} className="inline-flex items-center gap-1 rounded-md bg-accent px-2.5 py-1.5 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50">
            {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
          </button>
        </div>
      </div>
      <p className="mt-1.5 text-[11px] text-faint">Phone numbers are stored for the escalation matrix; live SMS/voice paging requires an SMS connector (operator-provisioned).</p>
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}

function DeleteBtn({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button onClick={() => start(() => deleteContact(id))} disabled={pending} title="Remove contact" className="shrink-0 text-faint transition hover:text-critical disabled:opacity-50">
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
    </button>
  );
}
