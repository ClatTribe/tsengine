"use client";

import { useState } from "react";
import Link from "next/link";
import { Loader2, Check, ArrowRight } from "lucide-react";

export function DemoForm() {
  const [form, setForm] = useState({ name: "", email: "", company: "", message: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  function set(k: keyof typeof form) {
    return (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, source: "demo-page" }),
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
