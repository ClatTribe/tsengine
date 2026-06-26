"use client";

import { useState, useTransition } from "react";
import { Wrench, Loader2, CircleAlert } from "lucide-react";
import { getFixGuidance, type FixPlan } from "@/app/(app)/compliance/[framework]/actions";

// "Get fix guidance" — runs the vCISO remediation agent over this framework's control gaps and renders
// the grounded, plain-English remediation plan. A named human still owns the decision to apply it.
export function FixGuidance({ framework }: { framework: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<FixPlan | null>(null);

  function run() {
    setRes(null);
    start(async () => setRes(await getFixGuidance(framework)));
  }

  return (
    <div className="space-y-4">
      <div>
        <button
          onClick={run}
          disabled={pending}
          className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3.5 py-2 text-sm font-medium text-accent transition hover:border-accent disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
          {pending ? "Drafting remediation…" : "Get fix guidance"}
        </button>
        {pending && <p className="mt-2 text-xs text-faint">The AI vCISO is drafting concrete steps for each gap — this can take a minute.</p>}
      </div>

      {res?.ok === false && (
        <div className="flex items-center gap-2 rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
          <CircleAlert className="h-4 w-4" /> {res.error}
        </div>
      )}
      {res?.ok && res.plan && (
        <div className="rounded-xl border border-border bg-surface p-5">
          <p className="whitespace-pre-line text-sm leading-relaxed text-muted">{res.plan}</p>
          <p className="mt-3 text-xs text-faint">
            AI-drafted guidance grounded in your findings. A named owner reviews + decides what to apply.
          </p>
        </div>
      )}
    </div>
  );
}
