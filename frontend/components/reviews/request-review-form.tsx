"use client";

import { useState, useTransition } from "react";
import { UserPlus, Loader2, Check } from "lucide-react";
import { submitReview } from "@/app/(app)/reviews/actions";
import type { Finding } from "@/lib/types";

// RequestReviewForm opens an expert review straight from the Reviews page — pick one of your findings
// + add a note. The existing RequestReview component is finding-detail-scoped (needs a subjectId); this
// one carries a picker so the Reviews tab isn't a dead-end with no way to escalate.
export function RequestReviewForm({ findings }: { findings: Finding[] }) {
  const [open, setOpen] = useState(false);
  const [findingId, setFindingId] = useState("");
  const [note, setNote] = useState("");
  const [done, setDone] = useState(false);
  const [pending, start] = useTransition();

  if (findings.length === 0) return null;

  if (!open) {
    return (
      <button
        onClick={() => { setDone(false); setOpen(true); }}
        className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover"
      >
        <UserPlus className="h-4 w-4" /> Request a review
      </button>
    );
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        start(async () => { await submitReview(findingId, note.trim()); setDone(true); setOpen(false); });
      }}
      className="card w-full max-w-md space-y-3 p-4 text-left"
    >
      <div className="flex items-center gap-2 text-sm font-semibold">
        <UserPlus className="h-4 w-4 text-accent" /> Ask an expert to weigh in
      </div>
      <label className="block text-xs text-muted">
        Which finding?
        <select
          value={findingId}
          onChange={(e) => setFindingId(e.target.value)}
          required
          className="mt-1 w-full rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm text-ink"
        >
          <option value="">Select a finding…</option>
          {findings.map((f) => (
            <option key={f.id} value={f.id}>
              [{f.severity}] {f.title}
            </option>
          ))}
        </select>
      </label>
      <label className="block text-xs text-muted">
        What do you want a second opinion on?
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={3}
          placeholder="e.g. Is this actually exploitable, or lower risk than it looks?"
          className="mt-1 w-full resize-none rounded-lg border border-border bg-surface px-2.5 py-1.5 text-sm text-ink outline-none focus:border-accent"
        />
      </label>
      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={pending || !findingId}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />} Send to an expert
        </button>
        <button type="button" onClick={() => setOpen(false)} className="text-xs text-muted transition hover:text-ink">
          Cancel
        </button>
      </div>
      {done && (
        <p className="inline-flex items-center gap-1 text-xs text-pulse">
          <Check className="h-3.5 w-3.5" /> Review requested.
        </p>
      )}
    </form>
  );
}
