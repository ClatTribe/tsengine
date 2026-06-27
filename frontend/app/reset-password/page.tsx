"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, Lock, ArrowLeft, CheckCircle2 } from "lucide-react";
import { LogoMark } from "@/components/brand/logo";

function ResetForm() {
  const router = useRouter();
  const params = useSearchParams();
  const email = params.get("email") ?? "";
  const token = params.get("token") ?? "";
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState("");

  const invalidLink = !email || !token;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    if (pw.length < 8) return setErr("Password must be at least 8 characters.");
    if (pw !== pw2) return setErr("Passwords don't match.");
    setBusy(true);
    const res = await fetch("/api/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, token, new_password: pw }),
    });
    if (res.ok) {
      setDone(true);
      setTimeout(() => router.push("/login"), 1800);
    } else {
      const b = await res.json().catch(() => ({}));
      setErr(b.error ?? "This reset link is invalid or has expired.");
    }
    setBusy(false);
  }

  if (done) {
    return (
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-card">
        <CheckCircle2 className="h-7 w-7 text-pulse" />
        <h1 className="mt-3 text-xl font-semibold tracking-tight">Password reset</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">Taking you to sign in…</p>
      </div>
    );
  }

  if (invalidLink) {
    return (
      <div className="rounded-2xl border border-border bg-surface p-6 shadow-card">
        <h1 className="text-xl font-semibold tracking-tight">Invalid reset link</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          This link is missing its token. Request a fresh one.
        </p>
        <Link href="/forgot-password" className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
          Request a new link
        </Link>
      </div>
    );
  }

  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight">Choose a new password</h1>
      <p className="mt-2 text-sm leading-relaxed text-muted">
        for <span className="font-medium text-ink">{email}</span>
      </p>
      <form onSubmit={submit} className="mt-7 space-y-4">
        {[
          { v: pw, set: setPw, ph: "New password", auto: "new-password" },
          { v: pw2, set: setPw2, ph: "Confirm new password", auto: "new-password" },
        ].map((f, i) => (
          <div key={i} className="flex items-center gap-2 rounded-xl border border-border bg-surface px-3 shadow-sm focus-within:border-accent">
            <Lock className="h-4 w-4 text-faint" />
            <input
              type="password"
              required
              autoComplete={f.auto}
              value={f.v}
              onChange={(e) => f.set(e.target.value)}
              placeholder={f.ph}
              className="w-full bg-transparent py-2.5 text-sm outline-none"
            />
          </div>
        ))}
        {err && <p className="text-sm text-red-600">{err}</p>}
        <button
          type="submit"
          disabled={busy}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Reset password"}
        </button>
      </form>
      <Link href="/login" className="mt-6 inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <ArrowLeft className="h-4 w-4" /> Back to sign in
      </Link>
    </>
  );
}

export default function ResetPasswordPage() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-sm animate-fade-rise">
        <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white shadow-sm">
            <LogoMark className="h-5 w-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">TensorShield</span>
        </Link>
        <Suspense fallback={<Loader2 className="h-5 w-5 animate-spin text-muted" />}>
          <ResetForm />
        </Suspense>
      </div>
    </main>
  );
}
