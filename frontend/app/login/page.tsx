"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Loader2, Lock, BadgeCheck, Sparkles, ArrowRight, Eye, EyeOff, Copy, Check } from "lucide-react";
import { LogoMark } from "@/components/brand/logo";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  // The second step: a correct password on an account with two-factor sign-in on lands here.
  const [needCode, setNeedCode] = useState(false);
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  // Returning from the identity provider: either it needs the person's own code, or it failed and the
  // reason rides in the URL (the callback route never leaves someone on a blank page).
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    if (q.get("step") === "code") setNeedCode(true);
    const ssoErr = q.get("sso_error");
    if (ssoErr) setErr(ssoErr);
  }, []);

  async function sso() {
    if (!email.trim()) {
      setErr("Enter your work email, then choose Sign in with SSO.");
      return;
    }
    setBusy(true);
    setErr("");
    const res = await fetch("/api/sso/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const b = await res.json().catch(() => ({}));
    if (res.ok && b.sso && b.authorize_url) {
      window.location.assign(b.authorize_url);
      return;
    }
    setBusy(false);
    setErr(res.ok ? "Your workspace does not use single sign-on — sign in with your password." : (b.error ?? "Single sign-on is unavailable."));
  }

  async function copyPassword() {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

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
      const b = await res.json().catch(() => ({}));
      if (b.two_factor_required) {
        // The password was right; nothing is signed in until the code is.
        setNeedCode(true);
        setBusy(false);
        return;
      }
      router.push("/dashboard");
      router.refresh();
    } else {
      const b = await res.json().catch(() => ({}));
      setErr(b.error ?? "Sign-in failed.");
      setBusy(false);
    }
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const res = await fetch("/api/session/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(useRecovery ? { recovery_code: code } : { code }),
    });
    const b = await res.json().catch(() => ({}));
    if (res.ok) {
      // A recovery code was spent: land on Settings, which shows how many are left — before the day
      // they are needed, not after.
      router.push(typeof b.recovery_codes_remaining === "number" ? "/settings" : "/dashboard");
      router.refresh();
      return;
    }
    setBusy(false);
    setCode("");
    if (b.expired) {
      // The sign-in expired or too many codes were wrong: back to the password, and say why.
      setNeedCode(false);
      setPassword("");
    }
    setErr(b.error ?? "That code is not right.");
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-2">
      {/* Form side */}
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm animate-fade-rise">
          <Link href="/" className="mb-10 inline-flex items-center gap-2.5">
            <LogoMark className="h-8 w-8" />
            <span className="text-base font-semibold tracking-tight">TensorShield</span>
          </Link>

          <h1 className="text-2xl font-semibold tracking-tight">Welcome back</h1>
          <p className="mt-1.5 text-sm text-muted">Your security team is standing by. Sign in to your workspace.</p>

          {needCode ? (
            <form onSubmit={verify} className="mt-8 space-y-4">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-muted">
                  {useRecovery ? "Recovery code" : "6-digit code from your authenticator app"}
                </label>
                <input
                  autoFocus
                  inputMode={useRecovery ? "text" : "numeric"}
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 font-mono text-sm tracking-widest shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
                  placeholder={useRecovery ? "xxxxx-xxxxx" : "123456"}
                />
              </div>
              <button
                type="submit"
                disabled={busy || !code.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                {busy ? "Checking…" : "Verify and sign in"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setUseRecovery((v) => !v);
                  setCode("");
                  setErr("");
                }}
                className="text-xs font-medium text-accent hover:underline"
              >
                {useRecovery ? "Use a code from my authenticator app" : "Lost your phone? Use a recovery code"}
              </button>
              {err && (
                <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>
              )}
            </form>
          ) : (
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
              <div className="mb-1.5 flex items-center justify-between">
                <label className="block text-xs font-medium text-muted">Password</label>
                <Link href="/forgot-password" className="text-xs font-medium text-accent hover:underline">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 pr-20 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
                  placeholder="••••••••••••"
                />
                <div className="absolute inset-y-0 right-2 flex items-center gap-1">
                  <button
                    type="button"
                    onClick={copyPassword}
                    disabled={!password}
                    aria-label={copied ? "Copied" : "Copy password"}
                    title={copied ? "Copied" : "Copy password"}
                    className="grid h-7 w-7 place-items-center rounded-lg text-muted transition hover:bg-white/5 hover:text-ink disabled:opacity-40"
                  >
                    {copied ? <Check className="h-4 w-4 text-accent" /> : <Copy className="h-4 w-4" />}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    title={showPassword ? "Hide password" : "Show password"}
                    className="grid h-7 w-7 place-items-center rounded-lg text-muted transition hover:bg-white/5 hover:text-ink"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>
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
            <button
              type="button"
              onClick={sso}
              disabled={busy}
              className="flex w-full items-center justify-center gap-2 rounded-xl border border-border px-3 py-2.5 text-sm font-medium text-ink transition hover:bg-white/5 disabled:opacity-60"
            >
              Sign in with SSO
            </button>
            {err && (
              <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>
            )}
          </form>
          )}

          <p className="mt-5 text-sm text-muted">
            New to TensorShield?{" "}
            <Link href="/signup" className="font-medium text-accent hover:underline">Create your workspace →</Link>
          </p>

          {/* Discoverability for the SEPARATE operator auth namespace (§18.5): an MSP/managed practitioner
              works their clients' queue at /operator, not a tenant login. */}
          <p className="mt-2 text-xs text-faint">
            Partner or managed practitioner?{" "}
            <Link href="/operator/login" className="font-medium text-muted hover:text-ink hover:underline">Operator console sign-in →</Link>
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