"use client";

import { useState, useTransition } from "react";
import Link from "next/link";
import { Sparkles, Loader2, X, CircleAlert, ArrowRight } from "lucide-react";
import { generateBrief, type Brief } from "@/app/(app)/brief/actions";
import { SeverityBadge } from "@/components/ui/primitives";

// The AI Security Engineer's presence ON the Security surface — sprinkled, not a page. When AI is on, the
// "Triage everything" action runs the whole-estate L2 triage INLINE (a modal right here) instead of
// navigating to a console; when off, it points to Settings → LLM to enable it. (This is why the engineer
// no longer "goes to /brief": the triage happens where the work is.) Grounded §10; HITL unchanged.
export function EngineerStrip({ aiEnabled }: { aiEnabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [brief, setBrief] = useState<Brief | null>(null);

  function run() {
    setOpen(true);
    setBrief(null);
    start(async () => setBrief(await generateBrief()));
  }

  if (!aiEnabled) {
    return (
      <Link
        href="/settings"
        className="group flex items-center gap-2.5 rounded-xl border border-border bg-surface px-4 py-2.5 text-sm transition hover:border-accent/40"
      >
        <Sparkles className="h-4 w-4 shrink-0 text-muted" />
        <span className="min-w-0 flex-1 text-muted">
          <span className="font-medium text-ink">Turn on your AI Security Engineer</span> to triage this list, rank by real
          impact, and explain every issue — beyond the deterministic scan.
        </span>
        <span className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-accent">
          Enable <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
        </span>
      </Link>
    );
  }

  return (
    <>
      <button
        onClick={run}
        className="group flex w-full items-center gap-2.5 rounded-xl border border-accent/30 bg-accent-soft/30 px-4 py-2.5 text-left text-sm transition hover:border-accent/60"
      >
        <Sparkles className="h-4 w-4 shrink-0 text-accent" />
        <span className="min-w-0 flex-1 text-muted">
          <span className="font-medium text-ink">Your AI Security Engineer is on.</span> Have it triage the whole estate —
          re-rank by real impact and explain every issue in plain English.
        </span>
        <span className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-accent">
          Triage everything <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
        </span>
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={() => setOpen(false)}>
          <div className="max-h-[82vh] w-full max-w-2xl overflow-auto rounded-2xl border border-border bg-bg p-5 shadow-elevated" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                <Sparkles className="h-4 w-4 text-accent" /> AI triage — your whole estate
              </div>
              <button onClick={() => setOpen(false)} className="text-faint transition hover:text-ink" aria-label="Close">
                <X className="h-4 w-4" />
              </button>
            </div>

            {pending && (
              <div className="flex items-center gap-2 text-sm text-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> The AI engineer is reading every finding and writing the brief — this can take a minute…
              </div>
            )}
            {brief?.ok === false && (
              <div className="flex items-center gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-critical">
                <CircleAlert className="h-4 w-4" /> {brief.error}
              </div>
            )}
            {brief?.ok && (
              <div className="space-y-4">
                {brief.summary?.executive_summary && <Block title="Executive summary" body={brief.summary.executive_summary} />}
                {brief.summary?.recommendations && <Block title="What to do next" body={brief.summary.recommendations} />}
                {(brief.reports?.length ?? 0) > 0 && (
                  <div>
                    <h3 className="mb-2 text-sm font-semibold text-ink">Prioritized issues</h3>
                    <div className="card divide-y divide-border">
                      {brief.reports!.slice(0, 8).map((f) => (
                        <div key={f.id} className="px-4 py-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={f.severity} />
                            <span className="text-sm font-medium text-ink">{f.title}</span>
                          </div>
                          {f.description && <p className="mt-1 text-sm leading-relaxed text-muted">{f.description}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!brief.summary?.executive_summary && (brief.reports?.length ?? 0) === 0 && (
                  <p className="text-sm text-muted">The engineer ran but produced no brief — try again, or run a scan first.</p>
                )}
                {brief.model && <p className="text-[11px] text-faint">Generated by {brief.model} — grounded in your real findings, nothing invented.</p>}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function Block({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <h3 className="mb-1 text-sm font-semibold text-ink">{title}</h3>
      <p className="whitespace-pre-line text-sm leading-relaxed text-muted">{body}</p>
    </div>
  );
}
