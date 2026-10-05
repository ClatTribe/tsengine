"use client";

import { useState, useTransition } from "react";
import { Wand2, Loader2, CircleAlert, Check, X, Minus } from "lucide-react";
import { getAutofix, type AutofixResult } from "@/app/(app)/findings/[id]/actions";

// "Generate AI fix" — runs the autofix agent for this finding and renders the LLM-generated, grounded
// code patch inline. A named human reviews + merges (the PR path stays the existing HITL-gated flow).
export function AutofixButton({ id }: { id: string }) {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<AutofixResult | null>(null);

  function run() {
    setRes(null);
    start(async () => setRes(await getAutofix(id)));
  }

  return (
    <div className="space-y-3">
      <button
        onClick={run}
        disabled={pending}
        className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-xs font-medium text-accent transition hover:border-accent disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wand2 className="h-3.5 w-3.5" />}
        {pending ? "Writing the patch…" : "Generate AI fix"}
      </button>

      {res?.ok === false && (
        <div className="flex items-center gap-2 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">
          <CircleAlert className="h-3.5 w-3.5" /> {res.error}
        </div>
      )}
      {res?.ok && res.fix && (
        <div className="rounded-xl border border-border bg-surface p-4">
          <p className="prose-fix whitespace-pre-wrap text-sm leading-relaxed text-muted">{res.fix}</p>
          <p className="mt-2 text-[11px] text-faint">AI-drafted patch grounded in this finding — review before you merge.</p>
          {res.soundness && res.soundness.checks.length > 0 && (
            <div className="mt-3 border-t border-border pt-3">
              <p className="mb-1.5 text-[11px] font-medium text-ink">Pre-delivery checks</p>
              <ul className="space-y-1">
                {res.soundness.checks.map((c) => (
                  <li key={c.name} className="flex items-start gap-1.5 text-[11px]">
                    {c.status === "pass" ? (
                      <Check className="mt-0.5 h-3 w-3 shrink-0 text-good" />
                    ) : c.status === "fail" ? (
                      <X className="mt-0.5 h-3 w-3 shrink-0 text-critical" />
                    ) : (
                      <Minus className="mt-0.5 h-3 w-3 shrink-0 text-faint" />
                    )}
                    <span className={c.status === "fail" ? "text-critical" : "text-muted"}>{c.message}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-1.5 text-[11px] text-faint">{res.soundness.note}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
