"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { ArrowRight, Loader2 } from "lucide-react";
import { operatorLogin } from "@/app/operator/actions";

export function OperatorLoginForm() {
  const [error, action] = useActionState(operatorLogin, null);
  return (
    <form action={action} className="card space-y-3 p-5">
      <label className="block text-xs font-medium text-muted">
        Email
        <input name="email" type="email" required autoComplete="username" className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink" />
      </label>
      <label className="block text-xs font-medium text-muted">
        Password
        <input name="password" type="password" required autoComplete="current-password" className="mt-1 w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-ink" />
      </label>
      {error && <p className="text-xs text-critical">{error}</p>}
      <Submit />
    </form>
  );
}

function Submit() {
  const { pending } = useFormStatus();
  return (
    <button type="submit" disabled={pending} className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50">
      {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <>Sign in <ArrowRight className="h-4 w-4" /></>}
    </button>
  );
}
