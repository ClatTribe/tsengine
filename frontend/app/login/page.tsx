"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, Loader2 } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [tenant, setTenant] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, tenant }),
    });
    if (res.ok) {
      router.push("/");
      router.refresh();
    } else {
      const b = await res.json().catch(() => ({}));
      setErr(b.error ?? "Sign-in failed.");
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm animate-fade-rise">
        <div className="mb-6 flex items-center gap-2.5">
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-accent/40 bg-accent-soft text-accent">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <div className="text-sm font-semibold leading-tight">Sentinel</div>
            <div className="text-xs text-muted">Security Command Center</div>
          </div>
        </div>

        <form onSubmit={submit} className="card space-y-4 p-6">
          <div>
            <label className="mb-1.5 block text-xs text-muted">Access token</label>
            <input
              type="password"
              autoFocus
              autoComplete="current-password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm outline-none transition focus:border-accent"
              placeholder="platform bearer token"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs text-muted">Tenant</label>
            <input
              type="text"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm outline-none transition focus:border-accent"
              placeholder="tenant id"
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2 text-sm font-medium text-bg transition hover:brightness-110 disabled:opacity-60"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {busy ? "Verifying…" : "Sign in"}
          </button>
          {err && <p className="text-xs text-critical">{err}</p>}
        </form>
        <p className="mt-3 text-center text-[11px] text-faint">
          The token is held server-side in an httpOnly cookie — never exposed to the browser.
        </p>
      </div>
    </main>
  );
}
