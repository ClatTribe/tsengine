"use client";

import { Check, Loader2, UserCheck } from "lucide-react";
import { acknowledgeIncident } from "@/app/(app)/incidents/actions";
import { useAction } from "@/lib/use-action";

// Acknowledge an open incident (the MDR "I'm on it") — stops the timed auto-escalation. When the
// incident is already acknowledged, shows who took ownership instead of the button.
export function AckButton({ id, acknowledged, by }: { id: string; acknowledged: boolean; by?: string }) {
  const [pending, run] = useAction();

  if (acknowledged) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-pulse-soft px-2 py-0.5 text-[10px] font-medium text-pulse">
        <UserCheck className="h-2.5 w-2.5" /> {by ? `ack · ${by}` : "acknowledged"}
      </span>
    );
  }

  return (
    <button
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        run(() => acknowledgeIncident(id), id);
      }}
      disabled={pending}
      title="Acknowledge — take ownership and stop auto-escalation"
      className="inline-flex shrink-0 items-center gap-1 rounded-full border border-border bg-surface px-2 py-0.5 text-[10px] font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Check className="h-2.5 w-2.5" />} Acknowledge
    </button>
  );
}
