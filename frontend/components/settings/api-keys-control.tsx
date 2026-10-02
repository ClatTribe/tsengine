"use client";

import { useState, useTransition } from "react";
import { KeyRound, Loader2, Plus, Copy, Check } from "lucide-react";
import { createAPIKey, revokeAPIKey } from "@/app/(app)/settings/actions";
import type { APIKey } from "@/lib/types";

const LIFETIMES = [
  { days: 30, label: "30 days" },
  { days: 90, label: "90 days" },
  { days: 180, label: "6 months" },
  { days: 365, label: "1 year" },
];

function fmt(ts?: string): string {
  if (!ts) return "";
  return new Date(ts).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

// Workspace API keys — what a CI job or a collector authenticates with instead of a person's session.
// The server decides everything that matters (scopes, expiry, who may mint); this renders its answer.
// The key is shown ONCE, from the create response, because the server keeps only a digest of it.
export function APIKeysControl({
  keys,
  scopes,
  canManage,
}: {
  keys: APIKey[];
  scopes: Record<string, string>;
  canManage: boolean;
}) {
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<string[]>(["ingest"]);
  const [days, setDays] = useState(90);
  const [err, setErr] = useState("");
  const [minted, setMinted] = useState<{ token: string; prefix: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [pending, start] = useTransition();
  const now = Date.now();

  function toggle(s: string) {
    setChosen((c) => (c.includes(s) ? c.filter((x) => x !== s) : [...c, s]));
  }

  function create() {
    setErr("");
    if (!name.trim()) return setErr("Name the key after what will use it — e.g. github-actions");
    if (chosen.length === 0) return setErr("Choose at least one scope");
    start(async () => {
      const r = await createAPIKey({ name: name.trim(), scopes: chosen, expires_in_days: days });
      if (!r.ok) return setErr(r.error);
      setMinted({ token: r.token, prefix: r.prefix });
      setCopied(false);
      setName("");
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <KeyRound className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">API keys</div>
          <div className="text-xs text-muted">
            For CI and collectors. A key can post data or read it — it can never approve a fix, accept a risk or change
            a setting, because those need a person.
          </div>
        </div>
      </div>

      {minted && (
        <div className="mt-3 rounded-lg border border-accent/40 bg-accent-soft/30 px-3 py-2.5">
          <div className="text-xs font-medium text-ink">Copy this key now — it is shown once and only a digest of it is stored.</div>
          <div className="mt-1.5 flex items-center gap-2">
            <code className="mono min-w-0 flex-1 truncate rounded bg-surface px-2 py-1 text-[11px] text-ink">{minted.token}</code>
            <button
              onClick={() => {
                void navigator.clipboard?.writeText(minted.token);
                setCopied(true);
              }}
              className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-1 text-[11px] text-muted hover:text-ink"
            >
              {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />} {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
      )}

      {keys.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {keys.map((k) => {
            const revoked = !!k.revoked_at;
            const expired = !revoked && new Date(k.expires_at).getTime() <= now;
            return (
              <li key={k.id} className="flex items-center gap-2.5 rounded-lg border border-border bg-surface px-2.5 py-2 text-xs">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2">
                    <span className="font-medium text-ink">{k.name}</span>
                    <code className="mono text-[11px] text-faint">{k.prefix}…</code>
                    {k.scopes.map((s) => (
                      <span key={s} className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted">{s}</span>
                    ))}
                  </div>
                  <div className="text-[11px] text-muted">
                    {revoked
                      ? `Revoked ${fmt(k.revoked_at)}${k.revoked_by ? ` by ${k.revoked_by}` : ""}`
                      : expired
                        ? `Expired ${fmt(k.expires_at)}`
                        : `Expires ${fmt(k.expires_at)}`}
                    {" · "}created by {k.created_by} · {k.last_used_at ? `last used ${fmt(k.last_used_at)}` : "never used"}
                  </div>
                </div>
                {canManage && !revoked && !expired && <RevokeBtn id={k.id} name={k.name} onError={setErr} />}
              </li>
            );
          })}
        </ul>
      )}

      {canManage ? (
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Name (e.g. github-actions)"
              className="min-w-[10rem] flex-1 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint"
            />
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              aria-label="Expires after"
              className="rounded-md border border-border bg-surface px-2 py-1.5 text-xs"
            >
              {LIFETIMES.map((l) => (
                <option key={l.days} value={l.days}>Expires after {l.label}</option>
              ))}
            </select>
            <button onClick={create} disabled={pending} className="inline-flex items-center gap-1 rounded-md bg-accent px-2.5 py-1.5 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50">
              {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />} Create key
            </button>
          </div>
          <div className="space-y-1">
            {Object.entries(scopes).map(([s, desc]) => (
              <label key={s} className="flex items-start gap-2 text-[11px] text-muted">
                <input type="checkbox" checked={chosen.includes(s)} onChange={() => toggle(s)} className="mt-0.5" />
                <span>
                  <span className="font-medium uppercase tracking-wide text-ink">{s}</span> — {desc}
                </span>
              </label>
            ))}
          </div>
        </div>
      ) : (
        <p className="mt-2 text-[11px] text-faint">Only the workspace owner can create or revoke keys.</p>
      )}
      {err && <p className="mt-1.5 text-[11px] text-critical">{err}</p>}
    </div>
  );
}

function RevokeBtn({ id, name, onError }: { id: string; name: string; onError: (e: string) => void }) {
  const [pending, start] = useTransition();
  return (
    <button
      disabled={pending}
      onClick={() => {
        if (!window.confirm(`Revoke "${name}"? Anything still using it will be refused from now on.`)) return;
        start(async () => {
          const r = await revokeAPIKey(id);
          if (!r.ok) onError(r.error);
        });
      }}
      className="shrink-0 rounded-md border border-border px-2 py-1 text-[11px] text-muted transition hover:border-critical/40 hover:text-critical disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Revoke"}
    </button>
  );
}
