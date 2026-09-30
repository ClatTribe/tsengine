"use client";

import { useState, useTransition } from "react";
import { Loader2, Target } from "lucide-react";
import { setExposureObjective } from "@/app/(app)/activity/actions";
import type { ExposureObjectiveSettings, ExposureVerdict } from "@/lib/types";

const WINDOWS = [
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
  { value: 0, label: "the whole history" },
];

// ExposureObjective answers "is this good?" for the trend above it. Three states, never two: MET,
// NOT MET, and NOT GRADED. The third is why this exists as its own component — a series too short,
// too mixed or too unmeasured to grade must never read as a miss (or as a pass). The server's reason
// and target are rendered verbatim, because the clause that failed lives in that wording.
export function ExposureObjective({ verdict, settings }: { verdict?: ExposureVerdict; settings?: ExposureObjectiveSettings }) {
  const declared = !!settings?.declared;
  const [editing, setEditing] = useState(!declared);
  const [windowDays, setWindowDays] = useState(settings?.window_days ?? 30);
  const [net, setNet] = useState(settings?.net_per_window ?? 0);
  const [proven, setProven] = useState(settings?.min_confirmed_fixed ?? 0);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  let tone = "text-muted";
  let label = "Not graded";
  if (verdict && declared && verdict.gradeable) {
    tone = verdict.met ? "text-pulse" : "text-high";
    label = verdict.met ? "Objective met" : "Objective not met";
  }

  return (
    <div className="mt-3 border-t border-border pt-3 text-xs">
      <div className="flex items-center gap-2">
        <Target className="h-3.5 w-3.5 shrink-0 text-muted" />
        {declared ? (
          <>
            <span className={`font-medium ${tone}`}>{label}</span>
            {verdict && <span className="text-subtle">· target: {verdict.target}</span>}
          </>
        ) : (
          <span className="font-medium text-ink">No objective set</span>
        )}
      </div>
      {verdict && <p className="mt-1 text-muted">{verdict.reason}</p>}

      {editing ? (
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-muted">
          <span>Over</span>
          <select value={windowDays} onChange={(e) => setWindowDays(Number(e.target.value))} aria-label="Window"
            className="rounded-lg border border-border bg-surface px-2 py-1 outline-none focus:border-accent">
            {WINDOWS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
          </select>
          <span>close at least</span>
          <input type="number" value={net} onChange={(e) => setNet(Number(e.target.value))} aria-label="Net closed minus opened"
            className="w-16 rounded-lg border border-border bg-surface px-2 py-1 outline-none focus:border-accent" />
          <span>more than open (0 = hold the line), with at least</span>
          <input type="number" min={0} value={proven} onChange={(e) => setProven(Math.max(0, Number(e.target.value)))} aria-label="Minimum proven closed"
            className="w-16 rounded-lg border border-border bg-surface px-2 py-1 outline-none focus:border-accent" />
          <span>fixes proven closed by re-test.</span>
          <button disabled={pending}
            onClick={() => start(async () => {
              const r = await setExposureObjective(windowDays, net, proven);
              if (r.ok) { setErr(""); setEditing(false); } else setErr(r.error);
            })}
            className="inline-flex items-center gap-1 rounded-lg border border-accent/40 bg-accent-soft px-2.5 py-1 font-medium text-accent hover:border-accent disabled:opacity-50">
            {pending && <Loader2 className="h-3 w-3 animate-spin" />} Save objective
          </button>
          {declared && <button onClick={() => setEditing(false)} className="text-faint hover:text-muted">Cancel</button>}
          {err && <span className="text-high">{err}</span>}
        </div>
      ) : (
        <button onClick={() => setEditing(true)} className="mt-1 text-faint hover:text-muted">Change objective</button>
      )}
    </div>
  );
}
