"use client";

import { useState } from "react";
import { Stamp, Loader2, Ban } from "lucide-react";
import type { AuditBlocker } from "@/lib/types";
import { issueCertificate } from "@/app/(app)/audit-signoff/actions";

// Issuing the certificate — the act the whole surface leads to, and the one most worth refusing.
//
// The BLOCKERS are rendered whether or not the reviewer has tried yet. A button that looks available
// and then fails is the shape that teaches people to click and see; showing what stands in the way
// while they work is what lets them clear it. All of them are shown at once for the same reason the
// server returns them that way — fixing one, re-submitting, and discovering the next is the slow loop
// this product exists to remove.
export function IssueCertificate({
  target,
  blockers,
  complete,
}: {
  target: string;
  blockers: AuditBlocker[];
  complete: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [notTested, setNotTested] = useState("");

  const blocked = blockers.length > 0;

  async function issue() {
    setBusy(true);
    setErr("");
    const extra = notTested.split("\n").map((s) => s.trim()).filter(Boolean);
    const res = await issueCertificate(target, extra);
    setBusy(false);
    if (!res.ok) setErr(res.error ?? "Could not issue the certificate.");
  }

  return (
    <section className="card space-y-3 px-5 py-4">
      <div className="flex items-center gap-2 text-sm font-medium text-ink">
        <Stamp className="h-4 w-4 text-accent" /> Certificate
      </div>

      {blocked ? (
        <div className="space-y-2">
          <p className="text-sm text-muted">This audit cannot be certified yet:</p>
          <ul className="space-y-1.5">
            {blockers.map((b) => (
              <li key={b.kind} className="flex items-start gap-2 text-sm text-muted">
                <Ban className="mt-0.5 h-3.5 w-3.5 shrink-0 text-high" />
                <span>{b.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-muted">
          Every finding has a decision and nothing serious is open. Issuing records the certificate
          under your name, with the firm and capacity taken from the practitioner roster.
        </p>
      )}

      {/* Anything the SCAN could not check is already carried onto the certificate from its own
          declared coverage gaps. This box is for limits only the auditor knows — scope agreed with
          the client, environments excluded, credentials never supplied. A certificate that lists
          only what was checked reads as though everything was. */}
      <label className="block space-y-1">
        <span className="text-[11px] uppercase tracking-wide text-muted">
          Not covered by this assessment (one per line)
        </span>
        <textarea
          rows={2}
          value={notTested}
          onChange={(e) => setNotTested(e.target.value)}
          placeholder="e.g. the payment flow was out of scope by agreement; no test credentials were supplied for the admin role"
          className="w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm"
        />
      </label>

      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={issue}
          disabled={busy || blocked || !complete}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Stamp className="h-3.5 w-3.5" />}
          {busy ? "Issuing…" : "Issue certificate"}
        </button>
        <span className="text-[11px] text-muted">
          The certificate states what was excluded, what remains open, what was not covered, and that it
          is not a guarantee.
        </span>
      </div>
      {err && <p className="text-xs text-high">{err}</p>}
    </section>
  );
}
