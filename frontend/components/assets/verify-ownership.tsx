"use client";

import { useState, useTransition } from "react";
import { ShieldCheck, Loader2, Copy, Check } from "lucide-react";
import { assetOwnershipChallenge, verifyAssetOwnership } from "@/app/(app)/assets/actions";

// VerifyOwnership — the one-click path out of autonomy gap T3.
//
// The engineer will not attempt to PROVE a finding against a target the customer has not shown they
// control. That gate is right and does not move. What was wrong is that it was SILENT: an unverified
// asset produced an empty proof queue, which looks exactly like an estate with nothing worth proving,
// and the only place to resolve it was inside a pentest engagement you had to create first.
//
// So it lives on the asset, where the blockage is caused, and states the consequence in the one sentence
// that matters: until this is done, nothing here gets proven.
//
// Grounded (§10): verification checks the LIVE target and records owner-verified ONLY when the token is
// really found. A DNS lookup failure or an absent file leaves it unverified — it never assumes, and the
// UI says which of the two happened rather than a generic failure.
type Challenge = { token?: string; dns_record?: string; file_path?: string; instructions?: string };

export function VerifyOwnership({ assetId, target }: { assetId: string; target: string }) {
  const [ch, setCh] = useState<Challenge | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [pending, start] = useTransition();

  const dns = ch?.dns_record || (ch?.token ? `_tsengine.${target} TXT ${ch.token}` : "");

  return (
    <div className="rounded-lg border border-medium/30 bg-medium/5 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-xs font-medium text-ink">
            <ShieldCheck className="h-3.5 w-3.5 text-medium" /> Ownership not verified
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            Findings here are still reported — but none will be <span className="font-medium text-ink">proven</span>.
            The engineer will not attack a target you have not shown you control.
          </p>
        </div>
        {!ch && (
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              setMsg(null);
              start(async () => setCh((await assetOwnershipChallenge(assetId)) as Challenge));
            }}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs font-medium text-ink transition hover:border-accent/40 disabled:opacity-50"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
            Verify
          </button>
        )}
      </div>

      {ch && (
        <div className="mt-3 space-y-2">
          <p className="text-xs text-muted">Publish either one, then check:</p>
          {dns && (
            <div className="flex items-center gap-2">
              <code className="mono min-w-0 flex-1 truncate rounded border border-border bg-bg px-2 py-1 text-[11px] text-ink">{dns}</code>
              <button
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText(dns);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }}
                className="shrink-0 rounded border border-border p-1.5 text-muted transition hover:text-ink"
                aria-label="Copy DNS record"
              >
                {copied ? <Check className="h-3 w-3 text-accent" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
          )}
          {ch.file_path && (
            <code className="mono block truncate rounded border border-border bg-bg px-2 py-1 text-[11px] text-ink">
              {ch.file_path}
            </code>
          )}
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              setMsg(null);
              start(async () => {
                const r = (await verifyAssetOwnership(assetId)) as { verified?: boolean; method?: string; error?: string };
                setMsg(
                  r?.verified
                    ? { ok: true, text: `Verified via ${r.method ?? "the published token"}. Proof is now enabled for this asset.` }
                    : { ok: false, text: r?.error || "Token not found yet — DNS can take a few minutes to propagate. Publish it, then check again." },
                );
              });
            }}
            className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-2.5 py-1.5 text-xs font-medium text-accent-ink disabled:opacity-50"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Check now
          </button>
        </div>
      )}

      {msg && (
        <p className={`mt-2 text-xs leading-relaxed ${msg.ok ? "text-accent" : "text-muted"}`}>{msg.text}</p>
      )}
    </div>
  );
}
