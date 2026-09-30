"use client";

import { useState, useTransition } from "react";
import { Loader2, Wrench } from "lucide-react";
import { prepareFixStep } from "@/app/(app)/fixes/actions";

// PrepareStep proposes one step's fixes through the approval desk. The label says so — "prepare",
// never "fix" — because nothing changes until a human approves, and the result line is the server's
// own account of what happened, not an optimistic guess.
export function PrepareStep({ stepKey, count }: { stepKey: string; count: number }) {
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  return (
    <div className="flex flex-col items-start gap-1">
      <button
        disabled={pending}
        onClick={() =>
          start(async () => {
            const r = await prepareFixStep(stepKey);
            setMsg(r.ok ? { ok: true, text: r.detail } : { ok: false, text: r.error });
          })
        }
        className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent transition hover:border-accent disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wrench className="h-3.5 w-3.5" />}
        Prepare {count === 1 ? "the fix" : `fixes for ${count} findings`} for approval
      </button>
      {msg && <p className={msg.ok ? "text-[11px] text-muted" : "text-[11px] text-high"}>{msg.text}</p>}
    </div>
  );
}
