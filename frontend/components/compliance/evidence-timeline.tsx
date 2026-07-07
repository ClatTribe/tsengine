"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Camera, Loader2, CircleAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { captureEvidence } from "@/app/(app)/compliance/[framework]/actions";
import type { EvidenceTimeline } from "@/lib/types";

// Continuous-evidence timeline — the SOC 2 Type II "prove it held across the window" view. Renders the
// captured posture snapshots (newest first) + a continuity summary, and a "Capture now" button that
// records an on-demand point (the monitoring loop also captures automatically). Honest: an un-monitored
// framework shows an empty state, and "continuous" is scoped to the captured points, not un-sampled time.
export function EvidenceTimelineView({ framework, timeline }: { framework: string; timeline: EvidenceTimeline }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [err, setErr] = useState<string | null>(null);
  const snaps = (timeline.snapshots ?? []).slice().reverse(); // newest first for display

  function capture() {
    setErr(null);
    start(async () => {
      const r = await captureEvidence(framework);
      if (!r.ok) setErr(r.error ?? "Could not capture evidence");
      else router.refresh(); // pull the freshly-appended snapshot
    });
  }

  const pct = Math.round(timeline.fully_met_ratio * 100);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-muted">
          {timeline.count > 0
            ? `${timeline.count} snapshot${timeline.count > 1 ? "s" : ""} · ${pct}% fully met across the window`
            : "No evidence captured yet — snapshots record automatically each monitoring pass."}
        </p>
        <button
          onClick={capture}
          disabled={pending}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Camera className="h-3.5 w-3.5" />}
          {pending ? "Capturing…" : "Capture now"}
        </button>
      </div>

      {timeline.count > 0 && (
        <div
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium ${
            timeline.continuous ? "bg-low/15 text-low" : "bg-accent-soft text-accent"
          }`}
        >
          {timeline.continuous ? <ShieldCheck className="h-3.5 w-3.5" /> : <TriangleAlert className="h-3.5 w-3.5" />}
          {timeline.continuous
            ? "Fully met at every captured point in the window"
            : "A gap appeared at one or more captured points"}
        </div>
      )}

      {err && (
        <div className="flex items-center gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
          <CircleAlert className="h-3.5 w-3.5" /> {err}
        </div>
      )}

      {snaps.length > 0 && (
        <ol className="space-y-1.5">
          {snaps.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
              <span className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 shrink-0 rounded-full ${s.fully_met ? "bg-low" : "bg-accent"}`}
                  aria-hidden
                />
                <span className="text-muted tabular-nums">{new Date(s.captured_at).toLocaleString()}</span>
              </span>
              <span className="text-faint tabular-nums">
                {s.met_controls}/{s.total_controls} met
                {s.gap_controls > 0 && <span className="text-high"> · {s.gap_controls} gap{s.gap_controls > 1 ? "s" : ""}</span>}
              </span>
            </li>
          ))}
        </ol>
      )}

      <p className="text-[11px] text-faint">
        Continuous evidence proves a control held <span className="font-medium">across the audit window</span> (SOC 2 Type II),
        not just at one moment. Scoped to captured points — a denser cadence is stronger evidence; it never claims the state at un-sampled instants.
      </p>
    </div>
  );
}
