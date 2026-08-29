"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { FileText, Lock, ExternalLink, Check, Clock, ShieldCheck } from "lucide-react";
import type { TrustDocEntry, TrustView } from "@/lib/types";

// The buyer's half of the Trust Center: what they can read now, what is behind the gate, and
// the two-step path through it (request access → accept the agreement).
//
// The gate decisions are the SERVER's — `readable`, `granted` and `nda_pending` are rendered,
// never re-derived. If this component computed them it would eventually disagree with the
// endpoint, and the visible failure of that is a row that looks open and 403s, or worse, a row
// that looks locked while its document is served.

function docIcon(e: TrustDocEntry) {
  if (!e.readable) return <Lock className="h-4 w-4" />;
  return e.generated ? <FileText className="h-4 w-4" /> : <ExternalLink className="h-4 w-4" />;
}

export function DocumentTier({
  tenant,
  token,
  access,
  data,
}: {
  tenant: string;
  token: string;
  access: string;
  data: TrustView;
}) {
  const router = useRouter();
  const docs = data.documents ?? [];
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [form, setForm] = useState({ email: "", name: "", company: "", reason: "" });
  const [ndaName, setNdaName] = useState("");

  const gated = docs.filter((d) => !d.readable);
  const readable = docs.filter((d) => d.readable);

  function docHref(e: TrustDocEntry) {
    const q = new URLSearchParams({ token, kind: e.kind });
    if (e.framework) q.set("framework", e.framework);
    if (access) q.set("access", access);
    return `/api/trust/${encodeURIComponent(tenant)}/doc?${q.toString()}`;
  }

  async function requestAccess(ev: React.FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`/api/trust/${encodeURIComponent(tenant)}/request?token=${encodeURIComponent(token)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const body = await res.json();
      if (!res.ok) {
        setError(body?.error ?? "Something went wrong. Try again in a moment.");
        return;
      }
      if (body.access_token) {
        // An auto-approve rule matched. The token goes in the URL so the page reloads as the
        // granted view and the buyer can bookmark or forward exactly what they were given.
        router.replace(`/trust/${tenant}?token=${encodeURIComponent(token)}&access=${encodeURIComponent(body.access_token)}`);
        router.refresh();
        return;
      }
      setPending(true);
    } catch {
      setError("Could not reach the server. Try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  async function acceptNDA(ev: React.FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError("");
    try {
      const q = new URLSearchParams({ token, access });
      const res = await fetch(`/api/trust/${encodeURIComponent(tenant)}/nda?${q.toString()}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: ndaName }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body?.error ?? "Could not record the acceptance.");
        return;
      }
      router.refresh();
    } catch {
      setError("Could not reach the server. Try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  if (docs.length === 0) return null;

  return (
    <div className="mx-auto mt-12 max-w-2xl">
      <h2 className="mb-1 text-center text-xs font-semibold uppercase tracking-wider text-faint">Documents</h2>
      <p className="mb-4 text-center text-[11px] text-faint">
        Generated live from {data.org}&apos;s security posture — not uploaded copies.
      </p>

      <div className="space-y-2">
        {readable.map((e) => (
          <a
            key={e.kind + (e.framework ?? "")}
            href={docHref(e)}
            target="_blank"
            rel="noopener noreferrer"
            className="card flex items-center gap-3 p-4 transition hover:border-accent/40"
          >
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">{docIcon(e)}</span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-ink">{e.title}</span>
              <span className="block text-xs text-muted">
                {e.note ? `${e.note} · ` : ""}
                {e.generated ? "Generated on open" : "Hosted externally"}
              </span>
            </span>
            <ExternalLink className="h-4 w-4 shrink-0 text-faint" />
          </a>
        ))}

        {gated.map((e) => (
          <div key={e.kind + (e.framework ?? "")} className="card flex items-center gap-3 p-4 opacity-80">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface-3 text-faint">{docIcon(e)}</span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-ink">{e.title}</span>
              <span className="block text-xs text-muted">{e.note ? `${e.note} · ` : ""}Available on request</span>
            </span>
          </div>
        ))}
      </div>

      {/* Step 2: approved, agreement outstanding. Shown before the request form so a buyer who
          has already been approved is not offered the thing they have finished doing. */}
      {data.nda_pending && (
        <form onSubmit={acceptNDA} className="card mt-4 p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <ShieldCheck className="h-4 w-4 text-accent" /> One step left
          </div>
          <p className="mt-1 text-xs text-muted">
            Accept the confidentiality agreement below to open the remaining documents.
          </p>
          <div className="mono mt-3 max-h-52 overflow-y-auto whitespace-pre-wrap rounded-lg border border-border bg-surface-2 p-3 text-[11px] leading-relaxed text-muted">
            {data.nda_text}
          </div>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <input
              required
              value={ndaName}
              onChange={(e) => setNdaName(e.target.value)}
              placeholder="Type your full name to accept"
              className="min-w-0 flex-1 rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <button
              disabled={busy}
              className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-60"
            >
              {busy ? "Recording…" : "Accept & continue"}
            </button>
          </div>
          {/* Said plainly because it is true and because a reader is entitled to know what is
              being kept about them. */}
          <p className="mt-2 text-[11px] text-faint">
            Your name, the time, and the exact text above are recorded as the record of this acceptance.
          </p>
        </form>
      )}

      {/* Step 1: nothing granted yet and there is something to unlock. */}
      {!data.granted && !data.nda_pending && gated.length > 0 && (
        <div className="card mt-4 p-5">
          {pending ? (
            <div className="flex items-start gap-3">
              <Clock className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
              <div>
                <div className="text-sm font-semibold text-ink">Request sent</div>
                <p className="mt-1 text-xs text-muted">
                  {data.org} will review it and email you an access link. Requests are usually answered within a
                  business day.
                </p>
              </div>
            </div>
          ) : (
            <form onSubmit={requestAccess}>
              <div className="text-sm font-semibold text-ink">Request the remaining documents</div>
              <p className="mt-1 text-xs text-muted">
                {data.nda_required
                  ? "You'll be asked to accept a confidentiality agreement once access is approved."
                  : "Access is granted for a limited period."}
              </p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <input
                  required
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="Work email"
                  className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <input
                  value={form.company}
                  onChange={(e) => setForm({ ...form, company: e.target.value })}
                  placeholder="Company"
                  className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Your name"
                  className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <input
                  value={form.reason}
                  onChange={(e) => setForm({ ...form, reason: e.target.value })}
                  placeholder="Why you need it (optional)"
                  className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm outline-none focus:border-accent"
                />
              </div>
              <button
                disabled={busy}
                className="mt-3 w-full rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-60 sm:w-auto"
              >
                {busy ? "Sending…" : "Request access"}
              </button>
            </form>
          )}
          {error && <p className="mt-2 text-xs text-high">{error}</p>}
        </div>
      )}

      {data.granted && (
        <p className="mt-4 flex items-center justify-center gap-1.5 text-xs text-muted">
          <Check className="h-3.5 w-3.5 text-pulse" /> You have access to {data.org}&apos;s full document set.
        </p>
      )}
    </div>
  );
}
