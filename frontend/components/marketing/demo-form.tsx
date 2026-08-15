"use client";

import { useState } from "react";
import Link from "next/link";
import { Loader2, Check, ArrowRight } from "lucide-react";

export function DemoForm() {
  const [form, setForm] = useState({ name: "", email: "", company: "", interest: "", message: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  function set(k: keyof typeof form) {
    return (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      // Two things were being dropped between this form and the sales inbox.
      //
      // 1. THE PLAN. Every paid CTA on /pricing links here as /demo?plan=core or ?plan=growth — that
      //    click is the highest-intent action on the site, and on the pentest tier it means "a customer's
      //    security review is blocking a deal". The form never read the query string, so sales received
      //    an undifferentiated lead and the intent was lost. Read at submit time from window.location
      //    rather than useSearchParams(): this is a click handler, so it is client-only by definition,
      //    and it avoids forcing a Suspense boundary / dynamic rendering on an otherwise static page.
      //    It rides on `source`, which the backend already defines as "where the form was submitted
      //    from (pricing, demo-page, …)" and already logs — so no API change is needed.
      //
      // 2. THE INTEREST ANSWER. The form collects `interest` and POSTs it, but leadRequest has no such
      //    field, so the server silently discarded whatever the person selected. Folding it into the
      //    message keeps the answer instead of throwing away something a human deliberately filled in.
      const plan = new URLSearchParams(window.location.search).get("plan")?.trim();
      const source = plan ? `pricing:${plan}` : "demo-page";
      const message = [form.interest && `Interest: ${form.interest}`, form.message].filter(Boolean).join("\n\n");
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, message, source }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) setError(data?.error ?? "Couldn't submit — try again.");
      else setDone(true);
    } catch {
      setError("Something went wrong — try again.");
    } finally {
      setLoading(false);
    }
  }

  if (done) {
    return (
      <div className="card flex flex-col items-center gap-3 p-8 text-center animate-fade-rise">
        <div className="grid h-12 w-12 place-items-center rounded-full bg-pulse/10 text-pulse">
          <Check className="h-6 w-6" />
        </div>
        <div className="text-lg font-semibold">Thanks — we&apos;ll be in touch.</div>
        <p className="max-w-sm text-sm text-muted">
          Our team will reach out shortly. In the meantime, you can start free and see your posture right away.
        </p>
        <Link href="/signup" className="mt-1 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover">
          Start free now <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card space-y-3 p-6 text-left">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" required value={form.name} onChange={set("name")} placeholder="Ada Lovelace" />
        <Field label="Work email" required type="email" value={form.email} onChange={set("email")} placeholder="ada@company.com" />
      </div>
      <Field label="Company" value={form.company} onChange={set("company")} placeholder="Acme Inc" />
      <div>
        <label className="mb-1 block text-xs font-medium text-muted">How do you want to work with us?</label>
        <select
          value={form.interest}
          onChange={set("interest")}
          className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink outline-none transition focus:border-accent"
        >
          <option value="">Not sure yet — help me decide</option>
          <option value="managed">Managed — run security &amp; compliance for me (a named expert)</option>
          <option value="self-serve">Self-serve — my team runs the product</option>
          <option value="msp-partner">MSP / consultancy — deliver it to my clients</option>
        </select>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-muted">What are you looking to solve?</label>
        <textarea
          value={form.message}
          onChange={set("message")}
          rows={3}
          placeholder="e.g. We need SOC 2 and a pentest report for an enterprise deal."
          className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent"
        />
      </div>
      {error && <div className="rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">{error}</div>}
      <button
        type="submit"
        disabled={loading}
        className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
      >
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {loading ? "Sending…" : "Request a demo"}
      </button>
      <p className="text-center text-[11px] text-faint">No spam. We&apos;ll only use your details to get in touch.</p>
    </form>
  );
}

function Field({
  label,
  required,
  type = "text",
  value,
  onChange,
  placeholder,
}: {
  label: string;
  required?: boolean;
  type?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-muted">
        {label} {required && <span className="text-accent">*</span>}
      </label>
      <input
        required={required}
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoCapitalize="off"
        className="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent"
      />
    </div>
  );
}
