"use client";

import { Loader2, Send, Check } from "lucide-react";
import { publishPolicy, ackPolicy } from "@/app/(app)/program/actions";
import { useAction } from "@/lib/use-action";

// PublishButton is the HITL publish — the authenticated user becomes the named owner (server-side).
export function PublishButton({ id }: { id: string }) {
  const [pending, run] = useAction();
  return (
    <button
      onClick={() => run(() => publishPolicy(id), id)}
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />} Publish
    </button>
  );
}

// AckButton lets the current user acknowledge a published policy. Shows acknowledged state when done.
export function AckButton({ id, acked }: { id: string; acked: boolean }) {
  const [pending, run] = useAction();
  if (acked) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-pulse">
        <Check className="h-3.5 w-3.5" /> You acknowledged
      </span>
    );
  }
  return (
    <button
      onClick={() => run(() => ackPolicy(id), id)}
      disabled={pending}
      className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 px-3 py-1.5 text-xs font-medium text-accent transition hover:bg-accent-soft disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />} I acknowledge
    </button>
  );
}
