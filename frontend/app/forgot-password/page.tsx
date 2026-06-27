"use client";

import { useState } from "react";
import Link from "next/link";
import { Loader2, Mail, ArrowLeft, CheckCircle2 } from "lucide-react";
import { LogoMark } from "@/components/brand/logo";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [err, setErr] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const res = await fetch("/api/forgot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (res.ok) {
      setSent(true);
    } else {
      const b = await res.json().catch(() => ({}));
      setErr(b.error ?? "Something went wrong. Try again.");
    }
    setBusy(false);
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm animate-fade-rise">
        <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
            <LogoMark className="h-5 w-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">TensorShield</span>
        </Link>

        {sent ? (
          <div className="rounded-2xl border border-border bg-surface p-6 shadow-card">
            <CheckCircle2 className="h-7 w-7 text-pulse" />
            <h1 className="mt-3 text-xl font-semibold tracking-tight">Check your email</h1>
            <p className="mt-2 text-sm leading-relaxed text-muted">
              If an account exists for <span className="font-medium text-ink">{email}</span>, we&apos;ve sent a
              link to reset your password. It expires in 1 hour.
            </p>
            <Link href="/login" className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
              <ArrowLeft className="h-4 w-4" /> Back to sign in
            </Link>
          </div>
        ) : (
          <>
            <h1 className="text-2xl font-semibold tracking-tight">Reset your password</h1>
            <p className="mt-2 text-sm leading-relaxed text-muted">
              Enter your work email and we&apos;ll send you a link to set a new password.
            </p>
            <form onSubmit={submit} className="mt-7 space-y-4">
              <label className="block">
                <span className="text-sm font-medium text-ink">Email</span>
                <div className="mt-1.5 flex items-center gap-2 rounded-xl border border-border bg-surface px-3 shadow-sm focus-within:border-accent">
                  <Mail className="h-4 w-4 text-faint" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full bg-transparent py-2.5 text-sm outline-none"
                  />
                </div>
              </label>
              {err && <p className="text-sm text-red-600">{err}</p>}
              <button
                type="submit"
                disabled={busy}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-60"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Send reset link"}
              </button>
            </form>
            <Link href="/login" className="mt-6 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
              <ArrowLeft className="h-4 w-4" /> Back to sign in
            </Link>
          </>
        )}
      </div>
    </main>
  );
}
