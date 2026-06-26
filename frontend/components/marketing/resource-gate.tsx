"use client";

import { useState } from "react";
import Link from "next/link";
import { Loader2, Lock, Check, ArrowRight, Printer } from "lucide-react";

// ResourceGate — captures an email (reused POST /api/lead, source "resource:<slug>") before revealing the
// gated resource content (children). On success it stores nothing client-side beyond local state; the content
// is already in the page (SSR), so unlock is instant and the resource stays printable/savable as a PDF.
export function ResourceGate({ slug, title, takeaways, children }: { slug: string; title: string; takeaways: string[]; children: React.ReactNode }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [unlocked, setUnlocked] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, company, message: `Resource: ${title}`, source: `resource:${slug}` }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) setError(data?.error ?? "Couldn't submit — try again.");
      else setUnlocked(true);
    } catch {
      setError("Something went wrong — try again.");
    } finally {
      setLoading(false);
    }
  }

  if (unlocked) {
    return (
      <div className="animate-fade-rise">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-pulse/30 bg-pulse/5 px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-medium text-ink">
            <Check className="h-4 w-4 text-pulse" /> Unlocked — it&apos;s yours. Print or save this page as a PDF to keep it.
          </div>
          <button onClick={() => window.print()} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs font-semibold text-ink transition hover:border-border-strong">
            <Printer className="h-3.5 w-3.5" /> Print / Save PDF
          </button>
        </div>
        {children}
        <div className="mt-10 rounded-2xl border border-border bg-surface p-8 text-center">
          <h3 className="text-xl font-semibold tracking-tight">Want this done for you, not just documented?</h3>
          <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-muted">
            The product closes the technical controls automatically; our managed expert handles the policies,
            attestations, and sign-offs. Or run it yourself — start free.
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/managed" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-2.5 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Have us run it
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      {/* what's inside */}
      <div>
        <div className="text-sm font-semibold uppercase tracking-wider text-accent">What&apos;s inside</div>
        <ul className="mt-4 space-y-3">
          {takeaways.map((t) => (
            <li key={t} className="flex items-start gap-2.5 text-sm leading-relaxed text-muted">
              <Check className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> {t}
            </li>
          ))}
        </ul>
      </div>
      {/* gate */}
      <form onSubmit={submit} className="card space-y-3 self-start p-6 text-left">
        <div className="flex items-center gap-2 text-sm font-semibold text-ink">
          <Lock className="h-4 w-4 text-accent" /> Get it free — enter your email
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" autoCapitalize="off"
            className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
          <input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Work email" autoCapitalize="off"
            className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        </div>
        <input value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Company (optional)" autoCapitalize="off"
          className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        {error && <div className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</div>}
        <button type="submit" disabled={loading}
          className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          {loading ? "Unlocking…" : "Unlock the resource"}
        </button>
        <p className="text-center text-[11px] text-faint">No spam. We&apos;ll send occasional security &amp; compliance tips — unsubscribe anytime.</p>
      </form>
    </div>
  );
}
