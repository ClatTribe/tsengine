"use client";

import { useState, useTransition } from "react";
import { Sparkles, Loader2, CircleAlert } from "lucide-react";
import { getAdvisorRoadmap, type Roadmap } from "@/app/(app)/compliance/[framework]/actions";

// "AI readiness roadmap" — runs the vCISO advisor over this framework's coverage + gaps + readiness and
// renders a prioritized, grounded audit-readiness roadmap. It never calls the customer "compliant" (an
// auditor attests that); a named human owns the plan.
export function AdvisorRoadmap({ framework }: { framework: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<Roadmap | null>(null);

  function run() {
    setRes(null);
    start(async () => setRes(await getAdvisorRoadmap(framework)));
  }

  return (
    <div className="space-y-4">
      <div>
        <button
          onClick={run}
          disabled={pending}
          className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3.5 py-2 text-sm font-medium text-accent transition hover:border-accent disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
          {pending ? "Building your roadmap…" : "AI readiness roadmap"}
        </button>
        {pending && <p className="mt-2 text-xs text-faint">The AI vCISO is prioritizing your path to audit-readiness — this can take a minute.</p>}
      </div>

      {res?.ok === false && (
        <div className="flex items-center gap-2 rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
          <CircleAlert className="h-4 w-4" /> {res.error}
        </div>
      )}
      {res?.ok && res.roadmap && (
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="whitespace-pre-line text-sm leading-relaxed text-muted">{res.roadmap}</p>
          <p className="mt-3 text-xs text-faint">
            AI-drafted, grounded in your live posture — not a compliance certification. A named auditor attests that.
          </p>
        </div>
      )}
    </div>
  );
}
