"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { ArrowRight, Loader2 } from "lucide-react";
import { operatorLogin, type LoginState } from "@/app/operator/actions";

// The operator sign-in. When the account has two-factor sign-in on, the server answers the password
// with a challenge (held in an httpOnly cookie, never here) and the form asks for the code — nothing
// is signed in until the code is accepted.
export function OperatorLoginForm() {
  const [state, action] = useActionState<LoginState, FormData>(operatorLogin, null);
  const needCode = !!state?.needCode;
  return (
    <form action={action} className="card space-y-3 p-5">
      {needCode ? (
        <label className="block text-xs font-medium text-muted">
          6-digit code from your authenticator app (or a recovery code)
          <input
            name="code"
            required
            autoFocus
            autoComplete="one-time-code"
            className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-sm tracking-widest text-ink"
          />
        </label>
      ) : (
        <>
          <label className="block text-xs font-medium text-muted">
            Email
            <input name="email" type="email" required autoComplete="username" className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink" />
          </label>
          <label className="block text-xs font-medium text-muted">
            Password
            <input name="password" type="password" required autoComplete="current-password" className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink" />
          </label>
        </>
      )}
      {state?.error && <p className="text-xs text-critical">{state.error}</p>}
      <Submit label={needCode ? "Verify and sign in" : "Sign in"} />
    </form>
  );
}

function Submit({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" disabled={pending} className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50">
      {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <>{label} <ArrowRight className="h-4 w-4" /></>}
    </button>
  );
}
