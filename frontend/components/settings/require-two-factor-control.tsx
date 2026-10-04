"use client";

import { useState, useTransition } from "react";
import { Loader2, Users } from "lucide-react";
import { setRequireTwoFactor } from "@/app/(app)/settings/actions";
import type { SecurityPolicy } from "@/lib/types";

// The owner's policy that every seat signs in with a second factor. Renders the server's policy and
// the server's list of who has NOT enrolled — by name, because the owner's next step is to tell those
// people, and switching a policy on without knowing who it will stop is how a security control becomes
// a support incident.
export function RequireTwoFactorControl({
  policy,
  canManage,
  ownerEnrolled,
}: {
  policy: SecurityPolicy;
  canManage: boolean;
  ownerEnrolled: boolean;
}) {
  const [pending, start] = useTransition();
  const [err, setErr] = useState("");
  const on = policy.require_two_factor;
  const gated = policy.without_two_factor ?? [];

  function toggle() {
    start(async () => {
      const r = await setRequireTwoFactor(!on);
      setErr(r.ok ? "" : r.error);
    });
  }

  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium">
            <Users className="h-4 w-4 text-muted" /> Require two-factor for everyone
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {on
              ? `Required${policy.required_by ? ` — switched on by ${policy.required_by}` : ""}. Anyone without it can sign in only to set it up.`
              : "Not required. Each person decides for themselves."}
          </p>
        </div>
        <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${on ? "bg-pulse-soft text-pulse" : "bg-medium/10 text-medium"}`}>
          {on ? "Required" : "Optional"}
        </span>
      </div>

      {gated.length > 0 ? (
        <p className="text-xs text-muted">
          {on ? "Waiting to set it up" : "Would be asked to set it up"} ({gated.length} of {policy.seats}):{" "}
          <span className="text-ink">{gated.join(", ")}</span>
        </p>
      ) : (
        <p className="text-xs text-muted">Everyone in this workspace has two-factor sign-in on.</p>
      )}

      {canManage && (
        <div>
          <button
            type="button"
            disabled={pending || (!on && !ownerEnrolled)}
            onClick={toggle}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink hover:bg-white/5 disabled:opacity-60"
          >
            {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {on ? "Stop requiring it" : "Require it"}
          </button>
          {!on && !ownerEnrolled && (
            <p className="mt-1 text-xs text-muted">Turn on two-factor for your own account first.</p>
          )}
        </div>
      )}
      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
    </div>
  );
}
