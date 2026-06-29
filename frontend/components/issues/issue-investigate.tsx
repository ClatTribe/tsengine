"use client";

import { useState, useTransition } from "react";
import { Telescope, Loader2, X, CircleAlert, Spline, Crosshair, Sparkles } from "lucide-react";
import { investigateIssue, type InvestigateResult } from "@/app/(app)/issues/actions";

// Per-issue "Investigate" — the agentic verb of the AI Security Engineer, sprinkled onto the Issues row
// (not a separate console). One click pulls the GROUNDED cross-surface picture for this one issue: the
// attack chain it sits on + its blast radius (deterministic, always), plus — when AI is on — the root
// cause and the right-layer fix. §10: the chain/blast-radius are real; the narrative rests on the finding.
export function IssueInvestigate({ issueKey, title }: { issueKey: string; title: string }) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [res, setRes] = useState<InvestigateResult | null>(null);

  function run() {
    setOpen(true);
    setRes(null);
    start(async () => setRes(await investigateIssue(issueKey)));
  }

  const d = res?.ok ? res.data : null;
  const blast = d?.blast_radius;

  return (
    <>
      <button
        onClick={run}
        title="Investigate this issue — cross-surface chain, blast radius, and the right-layer fix"
        className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-surface px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent"
      >
        <Telescope className="h-3 w-3" /> Investigate
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={() => setOpen(false)}>
          <div className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-2xl border border-border bg-bg p-5 shadow-elevated" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-ink">
                <Telescope className="h-4 w-4 text-accent" /> AI investigation
              </div>
              <button onClick={() => setOpen(false)} className="text-faint transition hover:text-ink" aria-label="Close">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="mb-4 truncate text-xs text-muted">{title}</p>

            {pending && (
              <div className="flex items-center gap-2 text-sm text-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> Tracing this issue across your code, cloud, and identity…
              </div>
            )}

            {res?.ok === false && (
              <div className="flex items-center gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-critical">
                <CircleAlert className="h-4 w-4" /> {res.error}
              </div>
            )}

            {d && (
              <div className="space-y-4">
                {/* Blast radius — the deterministic impact (always present, grounded) */}
                {blast?.reaches_crown_jewel ? (
                  <div className="flex items-start gap-2 rounded-xl border border-critical/30 bg-critical/10 px-3 py-2.5 text-sm">
                    <Crosshair className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
                    <span className="text-muted">
                      <span className="font-medium text-ink">Reaches a crown jewel</span>
                      {blast.crown_jewel_type ? <> ({blast.crown_jewel_type.replace(/_/g, " ")})</> : null}
                      {typeof blast.hops === "number" ? <> in {blast.hops} hop{blast.hops === 1 ? "" : "s"}</> : null} — this is why it
                      outranks its raw severity.
                    </span>
                  </div>
                ) : (
                  <p className="text-xs text-muted">No path to a crown jewel found — impact is this issue&apos;s own severity.</p>
                )}

                {/* Cross-surface chain — the deterministic edges this issue sits on */}
                {(d.chains?.length ?? 0) > 0 && (
                  <div>
                    <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-faint">
                      <Spline className="h-3.5 w-3.5" /> Attack chain
                    </div>
                    <div className="space-y-1.5">
                      {d.chains!.map((c, i) => (
                        <div key={i} className="mono rounded-lg border border-border bg-surface px-3 py-2 text-xs text-muted">{c}</div>
                      ))}
                    </div>
                  </div>
                )}

                {/* AI narrative — root cause + right-layer fix (only when AI is enabled) */}
                {d.ai_enabled ? (
                  <div className="space-y-3">
                    {d.summary?.executive_summary && (
                      <Block icon label="Root cause &amp; impact" body={d.summary.executive_summary} />
                    )}
                    {d.summary?.recommendations && <Block label="The fix (right layer)" body={d.summary.recommendations} />}
                    {!d.summary?.executive_summary && !d.summary?.recommendations && (
                      <p className="text-sm text-muted">The AI engineer ran but returned no narrative for this issue.</p>
                    )}
                    {d.model && <p className="text-[11px] text-faint">Model: {d.model} · grounded in this issue&apos;s findings, review before acting.</p>}
                  </div>
                ) : (
                  <div className="rounded-xl border border-border bg-surface px-3 py-2.5 text-sm text-muted">
                    <span className="inline-flex items-center gap-1.5 font-medium text-ink"><Sparkles className="h-3.5 w-3.5 text-accent" /> Turn on the AI Security Engineer</span>{" "}
                    {d.note}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function Block({ label, body, icon }: { label: string; body: string; icon?: boolean }) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-1.5 text-sm font-medium text-ink">
        {icon && <Sparkles className="h-3.5 w-3.5 text-accent" />} {label}
      </div>
      <p className="whitespace-pre-wrap text-sm leading-relaxed text-muted">{body}</p>
    </div>
  );
}
