"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Undo2, Loader2 } from "lucide-react";
import { reinstateAction } from "@/app/(app)/verify/actions";

// Putting a suppressed finding back. The reason is optional but prompted for: the override is
// recorded on the finding and in the ledger, and "why" is what makes it useful to the next reader.
export function ReinstateButton({ findingId }: { findingId: string }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const router = useRouter();

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="shrink-0 rounded-lg border border-border px-2.5 py-1.5 text-xs font-medium transition hover:border-border-strong"
      >
        <Undo2 className="mr-1 inline h-3.5 w-3.5" />
        Reinstate
      </button>
    );
  }

  return (
    <div className="w-64 shrink-0 space-y-2">
      <input
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why is this in scope? (optional)"
        className="w-full rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-xs outline-none focus:border-accent"
      />
      {err ? <p className="text-xs text-critical">{err}</p> : null}
      <div className="flex gap-2">
        <button
          disabled={pending}
          onClick={() =>
            startTransition(async () => {
              const res = await reinstateAction(findingId, reason);
              if (res?.error) {
                setErr(res.error);
                return;
              }
              setOpen(false);
              router.refresh();
            })
          }
          className="rounded-lg bg-accent px-2.5 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Put it back"}
        </button>
        <button
          onClick={() => { setOpen(false); setErr(null); }}
          className="rounded-lg px-2.5 py-1.5 text-xs text-muted transition hover:text-ink"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
