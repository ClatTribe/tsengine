"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, KeyRound, ArrowRight } from "lucide-react";
import { changePasswordAction } from "./actions";

// The set-a-new-password form. Used both for the forced first-login rotation (an invited
// member with a temp password) and a voluntary change. On success the same session stays
// valid, so we navigate straight back into the app.
export function ChangePasswordForm({ forced, email }: { forced: boolean; email: string }) {
  const router = useRouter();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    if (next !== confirm) {
      setErr("The two new passwords don't match.");
      return;
    }
    setBusy(true);
    const res = await changePasswordAction(current, next);
    if ("ok" in res) {
      router.push("/dashboard");
      router.refresh();
    } else {
      setErr(res.error);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mt-8 space-y-4">
      <div>
        <label className="mb-1.5 block text-xs font-medium text-muted">
          {forced ? "Temporary password" : "Current password"}
        </label>
        <input
          type="password"
          autoFocus
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
          placeholder={forced ? "the one-time password you were given" : "••••••••••••"}
        />
      </div>
      <div>
        <label className="mb-1.5 block text-xs font-medium text-muted">New password</label>
        <input
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
          placeholder="at least 8 characters"
        />
      </div>
      <div>
        <label className="mb-1.5 block text-xs font-medium text-muted">Confirm new password</label>
        <input
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm shadow-sm outline-none transition placeholder:text-faint focus:border-accent focus:ring-4 focus:ring-accent/10"
          placeholder="re-enter your new password"
        />
      </div>
      <button
        type="submit"
        disabled={busy}
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
        {busy ? "Saving…" : "Set new password"}
        {!busy && <ArrowRight className="h-4 w-4" />}
      </button>
      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
      {email && <p className="text-[11px] text-faint">Signed in as {email}</p>}
    </form>
  );
}
