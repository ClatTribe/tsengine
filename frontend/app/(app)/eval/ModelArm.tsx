"use client";

import { useState } from "react";
import { Cpu, Loader2 } from "lucide-react";

// The model arm of the eval, as a deliberate action rather than something the page does on render.
//
// The grading costs a model call per case on the customer's own key, so a dashboard that graded on
// every visit would spend their money to tell them something that had not changed. The button is
// the honesty: they choose when to pay for the answer.
type Ablation = {
  substrate_passed: number;
  model_passed: number;
  cases: number;
  delta: number;
  meaningful: boolean;
  verdict: string;
};

type RunResult = {
  ran: boolean;
  reason?: string;
  cases: number;
  model?: { passed: number; unanswered: number; note?: string };
  ablation?: Ablation;
  model_agreement?: number;
  substrate_agreement?: number;
};

export function ModelArm({ hasCases }: { hasCases: boolean }) {
  const [state, setState] = useState<"idle" | "running">("idle");
  const [result, setResult] = useState<RunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setState("running");
    setError(null);
    try {
      const res = await fetch("/api/eval-model", { method: "POST" });
      const data = await res.json();
      if (!res.ok) setError(data.error ?? "Could not grade your model.");
      else setResult(data);
    } catch {
      setError("Could not reach the grader.");
    } finally {
      setState("idle");
    }
  }

  return (
    <section className="rounded-2xl border border-border bg-surface px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Cpu className="h-4 w-4 text-muted" aria-hidden />
            Grade your model
          </h2>
          <p className="mt-1 max-w-prose text-xs text-muted">
            The score above is the deterministic filter. This asks the model you configured the same
            questions, graded against the same decisions your team made — so you can see whether your
            model helps on your estate, not on someone&rsquo;s benchmark.
          </p>
        </div>
        <button
          onClick={run}
          disabled={state === "running" || !hasCases}
          className="shrink-0 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink transition hover:bg-surface-2 disabled:opacity-50"
        >
          {state === "running" ? (
            <span className="flex items-center gap-1.5">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> Grading&hellip;
            </span>
          ) : (
            "Run"
          )}
        </button>
      </div>

      {!hasCases ? (
        <p className="mt-3 text-xs text-muted">
          There are no graded cases yet, so there is nothing to ask a model about.
        </p>
      ) : null}

      {error ? <p className="mt-3 text-xs text-critical">{error}</p> : null}

      {/* Not configured is reported as itself, never as a zero: a customer reading 0% would
          conclude their model is useless when the truth is we never asked it anything. */}
      {result && !result.ran ? <p className="mt-3 text-xs text-muted">{result.reason}</p> : null}

      {result?.ran && result.ablation ? (
        <div className="mt-4 space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-border px-4 py-3">
              <div className="text-2xl font-semibold text-ink">
                {result.ablation.substrate_passed}
                <span className="text-sm font-normal text-muted">/{result.ablation.cases}</span>
              </div>
              <div className="text-sm font-medium">Filter alone</div>
            </div>
            <div className="rounded-xl border border-border px-4 py-3">
              <div className="text-2xl font-semibold text-ink">
                {result.ablation.model_passed}
                <span className="text-sm font-normal text-muted">/{result.ablation.cases}</span>
              </div>
              <div className="text-sm font-medium">Your model</div>
              {result.model && result.model.unanswered > 0 ? (
                <div className="mt-0.5 text-xs text-muted">
                  {result.model.unanswered} unanswered, counted as missed
                </div>
              ) : null}
            </div>
          </div>
          <p className={result.ablation.meaningful ? "text-sm text-ink" : "text-xs text-muted"}>
            {result.ablation.verdict}
          </p>
          {result.model?.note ? <p className="text-xs text-muted">{result.model.note}</p> : null}
        </div>
      ) : null}
    </section>
  );
}
