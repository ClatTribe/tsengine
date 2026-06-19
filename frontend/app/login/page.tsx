"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ShieldCheck, Loader2, Lock, BadgeCheck, Sparkles, ArrowRight } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (res.ok) {
      router.push("/dashboard");
      router.refresh();
    } else {
      const b = await res.json().catch(() => ({}));
      setErr(b.error ?? "Sign-in failed.");
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-2">
      {/* Form side */}
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm animate-fade-rise">
          <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-xl bg-accent text-white shadow-sm">
              <ShieldCheck className="h-5 w-5" />
            </span>
            <span className="text-base font-semibold tracking-tight">TensorShield</span>
          </Link>

          <h1 className="text-2xl font-semibold tracking-tight">Welcome back</h1>
          <p className="mt-1.5 text-sm text-muted">Your security team is standing by. Sign in to your workspace.</p>

          <form onSubmit={submit} className="mt-8 space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted">Work email</label>
              <input
                type="email"
                autoFocus
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
                placeholder="you@company.com"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted">Password</label>
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
                placeholder="••••••••••••"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {busy ? "Signing in…" : "Sign in"}
              {!busy && <ArrowRight className="h-4 w-4" />}
            </button>
            {err && (
              <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>
            )}
          </form>

          <p className="mt-5 text-sm text-muted">
            New to TensorShield?{" "}
            <Link href="/signup" className="font-medium text-accent hover:underline">Create your workspace →</Link>
          </p>

          <div className="mt-4 flex items-center gap-2 text-[11px] text-faint">
            <Lock className="h-3.5 w-3.5" />
            Your session is held server-side in an httpOnly cookie — never exposed to the browser.
          </div>
        </div>
      </div>

      {/* Brand panel */}
      <div className="relative hidden overflow-hidden lg:block">
        <div className="absolute inset-0 bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]" />
        {/* soft glow accents */}
        <div className="absolute -right-24 -top-24 h-96 w-96 rounded-full bg-white/10 blur-3xl" />
        <div className="absolute -bottom-32 -left-16 h-96 w-96 rounded-full bg-pulse/20 blur-3xl" />

        <div className="relative flex h-full flex-col justify-center px-14 text-white">
          <div className="max-w-md">
            <span className="inline-flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1 text-xs font-medium text-white/90 ring-1 ring-white/15">
              <Sparkles className="h-3.5 w-3.5" /> AI security + compliance, with a human in the loop
            </span>
            <h2 className="mt-5 text-3xl font-semibold leading-tight tracking-tight">
              Your fractional security team, running while you build.
            </h2>
            <p className="mt-3 text-sm leading-relaxed text-white/70">
              TensorShield finds, triages, and fixes — and pulls you in only where judgment is needed. No security
              hire required.
            </p>

            {/* frosted posture preview */}
            <div className="mt-8 rounded-2xl bg-white/10 p-4 ring-1 ring-white/15 backdrop-blur">
              <div className="flex items-center justify-between">
                <span className="text-xs text-white/70">Security posture</span>
                <span className="inline-flex items-center gap-1.5 rounded-full bg-pulse/20 px-2 py-0.5 text-xs font-medium text-white ring-1 ring-pulse/30">
                  <span className="h-1.5 w-1.5 rounded-full bg-pulse" /> Protected
                </span>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                {[
                  ["0", "open issues"],
                  ["94%", "SOC 2"],
                  ["24/7", "monitored"],
                ].map(([n, l]) => (
                  <div key={l} className="rounded-xl bg-white/5 py-2.5">
                    <div className="text-lg font-semibold">{n}</div>
                    <div className="text-[10px] uppercase tracking-wide text-white/60">{l}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-8 flex items-center gap-5 text-xs text-white/70">
              <span className="inline-flex items-center gap-1.5">
                <BadgeCheck className="h-4 w-4" /> SOC 2 · ISO 27001 · PCI
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Lock className="h-4 w-4" /> Signed, tamper-evident evidence
              </span>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
