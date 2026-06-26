"use client";

import { useState, useTransition } from "react";
import { UserCheck, Loader2, Check } from "lucide-react";
import { flagForReview } from "@/app/(app)/saas-apps/actions";

// FlagForReview is the per-row action on the SaaS-apps page: escalate a risky third-party app or
// non-human identity to a human expert (the MSP/managed HITL). One click opens a review request that
// lands on /reviews — so a detection row isn't a dead-end, the founder has a next step.
export function FlagForReview({
  subject,
  name,
  note,
}: {
  subject: "saas_app" | "identity";
  name: string;
  note: string;
}) {
  const [done, setDone] = useState(false);
  const [pending, start] = useTransition();

  if (done) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-lg border border-pulse/30 bg-pulse-soft px-2.5 py-1 text-xs font-medium text-pulse">
        <Check className="h-3.5 w-3.5" /> In review
      </span>
    );
  }

  return (
    <button
      onClick={() => start(async () => { await flagForReview(subject, name, note); setDone(true); })}
      disabled={pending}
      title="Escalate this app to a human expert for a second opinion"
      className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-ink disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserCheck className="h-3.5 w-3.5" />} Flag for review
    </button>
  );
}
