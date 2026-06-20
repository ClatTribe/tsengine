"use client";

import { useState, useTransition } from "react";
import { EyeOff, Eye, Loader2 } from "lucide-react";
import { ignoreIssue, unignoreIssue } from "@/app/(app)/issues/actions";
import { cn } from "@/lib/utils";

const REASONS = [
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "false_positive", label: "False positive" },
  { value: "wont_fix", label: "Won't fix" },
];

// IssueActions is the issue-lifecycle control on a row: Ignore (with a reason)
// for an active issue, or Restore for a suppressed one. Drives the ledger-recorded
// /v1/issues/ignore|unignore endpoints via a server action.
export function IssueActions({ issueKey, ignored }: { issueKey: string; ignored?: boolean }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState(REASONS[0].value);
  const [pending, start] = useTransition();

  if (ignored) {
    return (
      <button
        onClick={() => start(() => unignoreIssue(issueKey))}
        disabled={pending}
        className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-ink disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />} Restore
      </button>
    );
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-muted transition hover:border-border-strong hover:text-ink"
      >
        <EyeOff className="h-3.5 w-3.5" /> Ignore
      </button>
    );
  }

  return (
    <div className="inline-flex items-center gap-1.5">
      <select
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        className="rounded-lg border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent"
      >
        {REASONS.map((r) => (
          <option key={r.value} value={r.value}>{r.label}</option>
        ))}
      </select>
      <button
        onClick={() => start(() => ignoreIssue(issueKey, reason, ""))}
        disabled={pending}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent transition hover:border-accent disabled:opacity-50",
        )}
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <EyeOff className="h-3.5 w-3.5" />} Confirm
      </button>
      <button onClick={() => setOpen(false)} className="text-xs text-faint hover:text-muted">Cancel</button>
    </div>
  );
}
