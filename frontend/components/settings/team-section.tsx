"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { UserPlus, Loader2, Copy, Check, Crown, User as UserIcon } from "lucide-react";
import type { User } from "@/lib/types";

// The Team section of Settings: lists members and (for owners) invites teammates. Invites
// return a one-time temp password the owner shares out-of-band — shown once, copyable.
export function TeamSection({ members, currentEmail, canInvite }: { members: User[]; currentEmail?: string; canInvite: boolean }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [invited, setInvited] = useState<{ email: string; temp: string } | null>(null);
  const [copied, setCopied] = useState(false);

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const res = await fetch("/api/team/invite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, name }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setInvited({ email, temp: data.temp_password });
      setEmail("");
      setName("");
      setOpen(false);
      router.refresh();
    } else {
      setErr(data.error ?? "Invite failed.");
    }
    setBusy(false);
  }

  return (
    <div className="card divide-y divide-border p-0">
      <ul className="divide-y divide-border">
        {members.map((m) => {
          const isOwner = m.role === "owner";
          const isYou = m.email === currentEmail;
          return (
            <li key={m.id} className="flex items-center gap-3 px-5 py-3">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-surface-2 text-muted">
                {isOwner ? <Crown className="h-4 w-4 text-accent" /> : <UserIcon className="h-4 w-4" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-sm font-medium">
                  {m.name || m.email}
                  {isYou && <span className="rounded-full bg-accent-soft px-1.5 py-0.5 text-[10px] font-medium text-accent">you</span>}
                </div>
                {m.name && <div className="truncate text-xs text-faint">{m.email}</div>}
              </div>
              <span className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium capitalize text-muted">{m.role}</span>
            </li>
          );
        })}
      </ul>

      {/* invite result — one-time temp password */}
      {invited && (
        <div className="space-y-2 bg-pulse-soft/40 px-5 py-4">
          <div className="text-sm font-medium text-pulse">Invited {invited.email}</div>
          <p className="text-xs text-muted">Share this one-time password with them — it won&apos;t be shown again:</p>
          <div className="flex items-center gap-2">
            <code className="mono flex-1 truncate rounded-lg border border-border bg-surface px-3 py-2 text-sm">{invited.temp}</code>
            <button
              onClick={() => { navigator.clipboard?.writeText(invited.temp); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
              className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-surface text-muted transition hover:text-ink"
              aria-label="Copy password"
            >
              {copied ? <Check className="h-4 w-4 text-pulse" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        </div>
      )}

      {/* invite form (owners only) */}
      {canInvite && (
        <div className="px-5 py-4">
          {open ? (
            <form onSubmit={invite} className="space-y-2.5">
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                  placeholder="teammate@company.com"
                  className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent"
                />
                <input
                  type="text" value={name} onChange={(e) => setName(e.target.value)}
                  placeholder="Name (optional)"
                  className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent"
                />
              </div>
              {err && <p className="text-xs text-critical">{err}</p>}
              <div className="flex items-center gap-2">
                <button
                  type="submit" disabled={busy}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
                >
                  {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserPlus className="h-3.5 w-3.5" />}
                  Send invite
                </button>
                <button type="button" onClick={() => { setOpen(false); setErr(""); }} className="text-xs text-muted hover:text-ink">Cancel</button>
              </div>
            </form>
          ) : (
            <button onClick={() => setOpen(true)} className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline">
              <UserPlus className="h-4 w-4" /> Invite a teammate
            </button>
          )}
        </div>
      )}
    </div>
  );
}
