"use client";

import { useState, useTransition } from "react";
import { KeyRound, Loader2, Copy, Check } from "lucide-react";
import { saveSSO } from "@/app/(app)/settings/actions";
import type { SSOSettings } from "@/lib/types";

// Single sign-on through the workspace's own identity provider. Renders the server's view (the client
// secret never comes back — only whether one is set) and the redirect URI to register at the provider,
// which is the step people most often get wrong. The server checks the issuer against the provider's
// own metadata before saving, so a typo is reported here rather than at everyone's next sign-in.
export function SSOControl({ sso, canManage }: { sso: SSOSettings; canManage: boolean }) {
  const [pending, start] = useTransition();
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState("");
  const [editing, setEditing] = useState(!sso.configured);
  const [issuer, setIssuer] = useState(sso.issuer ?? "");
  const [clientId, setClientId] = useState(sso.client_id ?? "");
  const [secret, setSecret] = useState("");
  const [enforced, setEnforced] = useState(sso.enforced);
  const [copied, setCopied] = useState(false);

  function save() {
    start(async () => {
      const r = await saveSSO({ issuer, client_id: clientId, client_secret: secret || undefined, enforced });
      if (!r.ok) return setErr(r.error);
      setErr("");
      setSecret("");
      setEditing(false);
      setSaved("Saved. The provider's sign-in metadata was checked and loads.");
    });
  }
  function remove() {
    start(async () => {
      const r = await saveSSO({ issuer: "" });
      if (!r.ok) return setErr(r.error);
      setErr("");
      setSaved("Single sign-on removed. Everyone signs in with a password again.");
      setIssuer("");
      setClientId("");
      setEditing(true);
    });
  }
  async function copy() {
    try {
      await navigator.clipboard.writeText(sso.redirect_uri);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  const input = "w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none focus:border-accent";
  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium">
            <KeyRound className="h-4 w-4 text-muted" /> Single sign-on (OIDC)
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {sso.configured
              ? `Signing in through ${sso.issuer}${sso.enforced ? " — passwords are off for everyone but the owner." : "."}`
              : "Not set up. Okta, Microsoft Entra ID, Google Workspace and any OpenID Connect provider work."}
          </p>
        </div>
        <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${sso.configured ? "bg-pulse-soft text-pulse" : "bg-medium/10 text-medium"}`}>
          {sso.configured ? (sso.enforced ? "Enforced" : "On") : "Off"}
        </span>
      </div>

      <div className="rounded-lg border border-border bg-surface px-3 py-2 text-xs">
        <div className="text-muted">Register this redirect URI at your identity provider:</div>
        <div className="mt-1 flex items-center gap-2">
          <code className="break-all font-mono text-ink">{sso.redirect_uri}</code>
          <button type="button" onClick={copy} className="text-muted hover:text-ink" aria-label="Copy redirect URI">
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      <p className="text-xs text-muted">
        Only people who already have a seat in this workspace can sign in through SSO — the provider is not a way to
        create accounts. SSO sessions last 12 hours, so removing someone at your provider takes effect the same day.
      </p>

      {canManage && editing && (
        <div className="space-y-2">
          <input className={input} placeholder="Issuer URL, e.g. https://acme.okta.com" value={issuer} onChange={(e) => setIssuer(e.target.value)} />
          <input className={input} placeholder="Client ID" value={clientId} onChange={(e) => setClientId(e.target.value)} />
          <input className={input} type="password" autoComplete="off"
            placeholder={sso.has_secret ? "Client secret (leave blank to keep the saved one)" : "Client secret"}
            value={secret} onChange={(e) => setSecret(e.target.value)} />
          <label className="flex items-start gap-2 text-xs text-muted">
            <input type="checkbox" checked={enforced} onChange={(e) => setEnforced(e.target.checked)} className="mt-0.5" />
            <span>
              Require SSO — turn off password sign-in for everyone except the owner, whose password stays as the way in if
              the provider is ever unavailable.
            </span>
          </label>
          <div className="flex gap-2">
            <button type="button" disabled={pending || !issuer.trim() || !clientId.trim()} onClick={save}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60">
              {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Check and save
            </button>
            {sso.configured && (
              <button type="button" onClick={() => setEditing(false)} className="rounded-lg border border-border px-3 py-1.5 text-xs">Cancel</button>
            )}
          </div>
        </div>
      )}
      {canManage && !editing && (
        <div className="flex gap-2">
          <button type="button" onClick={() => setEditing(true)} className="rounded-lg border border-border px-3 py-1.5 text-xs">Change</button>
          <button type="button" disabled={pending} onClick={remove} className="rounded-lg border border-border px-3 py-1.5 text-xs">Remove</button>
        </div>
      )}
      {saved && <p className="text-xs text-ink">{saved}</p>}
      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
    </div>
  );
}
