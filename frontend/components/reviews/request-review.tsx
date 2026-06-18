"use client";

import { useState, useTransition } from "react";
import { UserCheck, Check, Loader2 } from "lucide-react";
import { submitReview } from "@/app/(app)/findings/actions";
import { cn } from "@/lib/utils";

// "Request expert review" — the AI + human escalation. Opens an inline note field and
// files a ledger-signed review request; the agent keeps working, a human gets pulled in.
export function RequestReview({ subjectId, hasOpenReview }: { subjectId: string; hasOpenReview?: boolean }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [done, setDone] = useState(false);
  const [pending, start] = useTransition();

  if (done || hasOpenReview) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-pulse/30 bg-pulse/10 px-3 py-2 text-sm text-pulse">
        <Check className="h-4 w-4" /> Expert review requested — a human will weigh in.
      </div>
    );
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-accent/40 hover:text-ink"
      >
        <UserCheck className="h-3.5 w-3.5" /> Request expert review
      </button>
    );
  }

  function file() {
    start(async () => {
      await submitReview(subjectId, note.trim());
      setDone(true);
    });
  }

  return (
    <div className="card space-y-2 p-3">
      <div className="text-xs font-medium text-muted">Ask a security expert to review this finding</div>
      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="What are you unsure about? (optional)"
        rows={2}
        autoFocus
        className="w-full resize-none rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm outline-none transition focus:border-accent"
      />
      <div className="flex items-center gap-2">
        <button
          onClick={file}
          disabled={pending}
          className={cn(
            "inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-xs font-medium text-accent transition hover:border-accent disabled:opacity-50",
          )}
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <UserCheck className="h-3.5 w-3.5" />}
          {pending ? "Requesting…" : "Request review"}
        </button>
        <button onClick={() => setOpen(false)} className="text-xs text-faint transition hover:text-muted">
          Cancel
        </button>
      </div>
    </div>
  );
}
