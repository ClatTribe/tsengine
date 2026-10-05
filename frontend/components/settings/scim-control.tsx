"use client";

import { useState, useTransition } from "react";
import { Check, Copy, Loader2, Users } from "lucide-react";
import { mintSCIMToken, revokeSCIM } from "@/app/(app)/settings/actions";
import type { SCIMSettings } from "@/lib/types";

// SCIM provisioning: the company's identity provider creates a seat when someone is assigned the app and
// DEACTIVATES it when they leave — the half single sign-on does not do.
//
// The token is shown ONCE, in the response that minted it, and is not retrievable afterwards (only its
// digest is stored). Provisioning creates seats in the role chosen here and never an owner; a person the
// provider unassigns is deactivated, not deleted, and their sessions end. All of that is the server's
// rule — the page renders the counts and dates the server reports.

const fmt = (s?: string) => (s ? new Date(s).toLocaleString() : "");

export function SCIMControl({ initial, canManage }: { initial: SCIMSettings; canManage: boolean }) {
  const [s, setS] = useState(initial);
  const [role, setRole] = useState<string>(initial.default_role ?? "member");
  const [token, setToken] = useState("");
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function mint() {
    setErr("");
    start(async () => {
      const r = await mintSCIMToken(role);
      if (!r.ok) return setErr(r.error);
      setToken(r.token ?? "");
      setS({ ...r, token: undefined });
    });
  }

  function revoke() {
    setErr("");
    start(async () => {
      const r = await revokeSCIM();
      if (!r.ok) return setErr(r.error);
      setToken("");
      setS(r);
    });
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="flex items-start gap-2">
        <Users className="mt-0.5 h-4 w-4 text-muted" />
        <div>
          <div className="text-sm font-medium">Provisioning from your identity provider (SCIM)</div>
          <p className="mt-0.5 text-xs text-muted">
            {s.configured
              ? `On. ${s.provisioned} seat(s) created by your identity provider; ${s.deactivated} deactivated. New seats are ${s.default_role}s.`
              : "Off. Seats are invited by hand, and someone who leaves keeps their seat until it is removed here."}
          </p>
          {s.configured && (
            <p className="mt-0.5 text-xs text-muted">
              Token {s.token_prefix} · created by {s.created_by} {fmt(s.created_at)} ·{" "}
              {s.last_used_at ? `last used ${fmt(s.last_used_at)}` : "not used yet"}
            </p>
          )}
        </div>
      </div>

      <div className="text-xs text-muted">
        SCIM base URL: <code className="font-mono text-ink">{s.base_url}</code>
      </div>

      {token && (
        <div className="space-y-1.5 rounded-lg border border-medium/30 bg-medium/5 p-3">
          <p className="text-xs font-medium text-ink">
            Paste this token into your identity provider now. It is shown once and cannot be shown again.
          </p>
          <code className="block break-all rounded border border-border bg-surface px-2 py-1.5 font-mono text-xs">{token}</code>
          <button type="button" onClick={copy} className="inline-flex items-center gap-1.5 rounded-lg border border-border px-2.5 py-1 text-xs">
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />} {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}

      {canManage && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted">New seats are</span>
          <select value={role} onChange={(e) => setRole(e.target.value)} className="rounded-lg border border-border bg-surface px-2 py-1 text-xs">
            <option value="member">members</option>
            <option value="employee">employees (training and policies only)</option>
            <option value="auditor">auditors (read-only)</option>
          </select>
          <button
            type="button"
            disabled={pending}
            onClick={mint}
            className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 font-semibold text-white disabled:opacity-60"
          >
            {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} {s.configured ? "Rotate token" : "Turn on"}
          </button>
          {s.configured && (
            <button type="button" disabled={pending} onClick={revoke} className="rounded-lg border border-border px-3 py-1.5 font-medium disabled:opacity-60">
              Turn off
            </button>
          )}
        </div>
      )}
      {s.configured && canManage && (
        <p className="text-[11px] text-faint">Rotating ends the old token immediately — update your identity provider in the same sitting.</p>
      )}
      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
    </div>
  );
}
