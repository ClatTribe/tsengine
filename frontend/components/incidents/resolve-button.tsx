"use client";

import { useState, useTransition } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import { resolveIncident } from "@/app/(app)/incidents/actions";

// Close an incident, with the reason. A reason is required (the server refuses an empty one): "closed"
// with no reason reads, months later, exactly like "dismissed without looking".
export function ResolveButton({ id, event }: { id: string; event: boolean }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  if (!open) {
    return (
      <button
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen(true);
        }}
        title={event ? "This records an event; it stays open until a person closes it" : "Close it now, with the reason"}
        className="inline-flex shrink-0 items-center gap-1 rounded-full border border-border bg-surface px-2 py-0.5 text-[10px] font-medium text-muted transition hover:border-accent/40 hover:text-accent"
      >
        <CheckCircle2 className="h-2.5 w-2.5" /> Close
      </button>
    );
  }
  return (
    <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
      <input
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why — benign, contained, fixed…"
        className="w-56 rounded border border-border bg-surface px-2 py-0.5 text-[11px]"
      />
      <button
        disabled={pending || !reason.trim()}
        onClick={(e) => {
          e.preventDefault();
          start(async () => {
            const r = await resolveIncident(id, reason.trim());
            if (!r.ok) setErr(r.error ?? "could not close");
          });
        }}
        className="inline-flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-[10px] font-semibold text-white disabled:opacity-50"
      >
        {pending && <Loader2 className="h-2.5 w-2.5 animate-spin" />} Close
      </button>
      {err && <span className="text-[10px] text-critical">{err}</span>}
    </span>
  );
}
