"use client";

import { useState, useTransition } from "react";
import { Lock, X, Check, Loader2 } from "lucide-react";
import { setLoginFlow } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

// LoginFlowConfig configures authenticated scanning for a web asset (the common form-login case):
// the owner enters the login POST + a validate URL + a success marker; the scanner replays it and
// confirms the session each scan so it never silently scans logged-out (the FN guard). Credentials
// are sealed server-side and never returned.
export function LoginFlowConfig({ assetId }: { assetId: string }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [result, setResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const [f, setF] = useState({
    loginUrl: "",
    userField: "username",
    username: "",
    passField: "password",
    password: "",
    validateUrl: "",
    successMarker: "",
  });

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const canSubmit = f.loginUrl && f.username && f.password && f.validateUrl;

  function submit() {
    setResult(null);
    start(async () => setResult(await setLoginFlow(assetId, f)));
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
      >
        <Lock className="h-3 w-3" /> Auth
      </button>

      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4" onClick={() => setOpen(false)}>
          <div className="card w-full max-w-md p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold">
                <Lock className="h-4 w-4 text-accent" /> Authenticated scanning
              </h3>
              <button onClick={() => setOpen(false)} className="text-faint hover:text-ink">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mb-4 text-xs leading-relaxed text-muted">
              The scanner logs in with these credentials and re-checks the session each scan, so it
              never silently scans logged-out. Credentials are encrypted at rest and never shown again.
            </p>

            <div className="space-y-3">
              <Field label="Login URL (POST)" value={f.loginUrl} onChange={set("loginUrl")} placeholder="https://app.example.com/login" />
              <div className="grid grid-cols-2 gap-3">
                <Field label="Username field" value={f.userField} onChange={set("userField")} placeholder="username" />
                <Field label="Username" value={f.username} onChange={set("username")} placeholder="scanner@example.com" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Password field" value={f.passField} onChange={set("passField")} placeholder="password" />
                <Field label="Password" type="password" value={f.password} onChange={set("password")} placeholder="••••••••" />
              </div>
              <Field label="Validate URL (an authed page)" value={f.validateUrl} onChange={set("validateUrl")} placeholder="https://app.example.com/account" />
              <Field label="Success marker (logged-in text)" value={f.successMarker} onChange={set("successMarker")} placeholder="Sign out" />
            </div>

            {result?.error && <p className="mt-3 text-xs text-critical">{result.error}</p>}
            {result?.ok && (
              <p className="mt-3 flex items-center gap-1 text-xs text-pulse">
                <Check className="h-3.5 w-3.5" /> Saved — authenticated scanning is configured.
              </p>
            )}

            <div className="mt-4 flex justify-end gap-2">
              <button onClick={() => setOpen(false)} className="rounded-lg px-3 py-1.5 text-xs text-muted hover:text-ink">
                Close
              </button>
              <button
                onClick={submit}
                disabled={!canSubmit || pending}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50",
                  "border-accent/40 bg-accent-soft text-accent hover:border-accent",
                )}
              >
                {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Lock className="h-3.5 w-3.5" />}
                {pending ? "Saving…" : "Save login flow"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Field({
  label,
  ...props
}: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{label}</span>
      <input
        {...props}
        className="w-full rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-sm outline-none transition focus:border-accent/50"
      />
    </label>
  );
}
