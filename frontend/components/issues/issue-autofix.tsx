"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { Wand2, Loader2, X, CircleAlert, ArrowUpRight } from "lucide-react";
import { getAutofix, type AutofixResult } from "@/app/(app)/findings/[id]/actions";

// Per-issue one-click AI Fix — the agentic auto-fix where the user actually triages (the Issues list),
// not only buried on the finding detail. Triggers the autofix agent for the issue's representative finding
// and shows the grounded patch in a modal. A named human reviews + merges (the apply/PR path stays the
// existing HITL-gated flow); §10: the patch is grounded in the real finding, never invented.
export function IssueAutofix({ findingId, title }: { findingId: string; title: string }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [res, setRes] = useState<AutofixResult | null>(null);

  function run() {
    setOpen(true);
    setRes(null);
    start(async () => setRes(await getAutofix(findingId)));
  }

  return (
    <>
      <button
        onClick={run}
        title="Generate an AI fix for this issue"
        className="inline-flex shrink-0 items-center gap-1 rounded-md border border-accent/40 bg-accent-soft px-2 py-1 text-[11px] font-medium text-accent transition hover:border-accent"
      >
        <Wand2 className="h-3 w-3" /> AI Fix
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 text-left" onClick={() => setOpen(false)}>
          <div
            className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-2xl border border-border bg-bg p-5 shadow-elevated"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                <Wand2 className="h-4 w-4 text-accent" /> AI fix
              </div>
              <button onClick={() => setOpen(false)} className="text-faint transition hover:text-ink" aria-label="Close">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mb-3 truncate text-xs text-muted">{title}</p>

            {pending && (
              <div className="flex items-center gap-2 text-sm text-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> The AI security engineer is writing the patch — this can take a minute…
              </div>
            )}
            {res?.ok === false && (
              <div className="flex items-center gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-critical">
                <CircleAlert className="h-4 w-4" /> {res.error}
              </div>
            )}
            {res?.ok && res.fix && (
              <>
                <pre className="whitespace-pre-wrap rounded-xl border border-border bg-surface p-4 text-sm leading-relaxed text-muted">{res.fix}</pre>
                <p className="mt-2 text-[11px] text-faint">AI-drafted patch grounded in this finding — review before you merge.</p>
              </>
            )}

            <div className="mt-4 flex justify-end">
              <Link href={`/findings/${findingId}`} className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
                Open finding <ArrowUpRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
