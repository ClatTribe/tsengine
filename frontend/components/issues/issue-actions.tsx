"use client";

import { useState } from "react";
import { EyeOff, Eye, Loader2 } from "lucide-react";
import { ignoreIssue, unignoreIssue } from "@/app/(app)/issues/actions";
import { useAction } from "@/lib/use-action";
import { cn } from "@/lib/utils";

// A risk decision (anything but a false positive) is reviewed again after this many days. Shown as a
// visible choice with 90 pre-selected — never a silent default — and capped at a year server-side,
// because "accepted forever" is not a risk decision.
const REVIEW_DAYS = [
  { value: 30, label: "Review in 30 days" },
  { value: 90, label: "Review in 90 days" },
  { value: 180, label: "Review in 6 months" },
  { value: 365, label: "Review in 1 year" },
];

const REASONS = [
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "false_positive", label: "False positive" },
  { value: "wont_fix", label: "Won't fix" },
];

// IssueActions is the issue-lifecycle control on a row: Ignore (with a reason)
// for an active issue, or Restore for a suppressed one. Drives the ledger-recorded
// /v1/issues/ignore|unignore endpoints via a server action.
//
// canDecideRisk: accepting a risk (or won't-fix) is the workspace owner's decision and the server
// refuses it from anyone else (owner_scope.go), so a member is offered only "false positive" — the
// triage call they may make. Offering the others would fail silently behind useAction's refresh.
export function IssueActions({ issueKey, ignored, canDecideRisk = true }: { issueKey: string; ignored?: boolean; canDecideRisk?: boolean }) {
  const reasons = canDecideRisk ? REASONS : REASONS.filter((r) => r.value === "false_positive");
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState(reasons[0].value);
  const [reviewDays, setReviewDays] = useState(90);
  const needsReview = reason !== "false_positive";
  const [pending, run] = useAction();

  if (ignored) {
    return (
      <button
        onClick={() => run(() => unignoreIssue(issueKey), issueKey)}
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
        {reasons.map((r) => (
          <option key={r.value} value={r.value}>{r.label}</option>
        ))}
      </select>
      {needsReview && (
        <select
          value={reviewDays}
          onChange={(e) => setReviewDays(Number(e.target.value))}
          aria-label="Review date"
          className="rounded-lg border border-border bg-surface px-2 py-1 text-xs outline-none focus:border-accent"
        >
          {REVIEW_DAYS.map((d) => (
            <option key={d.value} value={d.value}>{d.label}</option>
          ))}
        </select>
      )}
      <button
        onClick={() => run(() => ignoreIssue(issueKey, reason, "", needsReview ? reviewDays : undefined), issueKey)}
        disabled={pending}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent transition hover:border-accent disabled:opacity-50",
        )}
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <EyeOff className="h-3.5 w-3.5" />} Confirm
      </button>
      {!canDecideRisk && <span className="text-[11px] text-faint">accepting a risk is the owner&apos;s call</span>}
      <button onClick={() => setOpen(false)} className="text-xs text-faint hover:text-muted">Cancel</button>
    </div>
  );
}
