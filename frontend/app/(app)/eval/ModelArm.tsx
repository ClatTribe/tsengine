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

type Trend = {
  comparable?: boolean;
  direction?: string;
  delta_points?: number;
  note?: string;
  model_changed?: boolean;
  previous_model?: string;
};

type Starter = {
  ran: boolean;
  cases?: number;
  passed?: number;
  unanswered?: number;
  unanswered_reason?: string;
  balance?: { keep: number; suppress: number };
  what_it_is?: string;
};

type RunResult = {
  ran: boolean;
  starter?: Starter;
  reason?: string;
  cases: number;
  model_name?: string;
  model?: { passed: number; unanswered: number; note?: string; unanswered_reason?: string };
  ablation?: Ablation;
  trend?: Trend;
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
          disabled={state === "running"}
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
          You have no graded cases yet, so there is nothing from your estate to ask about — but the
          starter check below works today, and is the point of running this on day one.
        </p>
      ) : null}

      {error ? <p className="mt-3 text-xs text-critical">{error}</p> : null}

      {/* Not configured is reported as itself, never as a zero: a customer reading 0% would
          conclude their model is useless when the truth is we never asked it anything. */}
      {result && !result.ran ? <p className="mt-3 text-xs text-muted">{result.reason}</p> : null}

      {/* A workspace with no graded cases still gets the starter check — that case is exactly who
          it exists for, and the ablation block below has nothing to show them. */}
      {result?.ran && !result.ablation?.cases && result.starter?.ran ? (
        <div className="mt-4">
          <StarterBlock s={result.starter} />
        </div>
      ) : null}

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
              <div className="text-sm font-medium">
                {result.model_name && result.model_name !== "platform default"
                  ? result.model_name
                  : "Your model"}
              </div>
              {result.model && result.model.unanswered > 0 ? (
                <div className="mt-0.5 text-xs text-muted">
                  {result.model.unanswered} unanswered, counted as missed
                  {/* Naming the cause matters: a wrong key, a rate limit and a chatty model all
                      look identical as a bare count, and only one of them is the customer's to
                      fix. */}
                  {result.model.unanswered_reason ? ` — ${result.model.unanswered_reason}` : null}
                </div>
              ) : null}
            </div>
          </div>
          <p className={result.ablation.meaningful ? "text-sm text-ink" : "text-xs text-muted"}>
            {result.ablation.verdict}
          </p>
          {result.model?.note ? <p className="text-xs text-muted">{result.model.note}</p> : null}

          {result.starter?.ran ? <StarterBlock s={result.starter} /> : null}

          {/* Model runs get their own history, so switching models is visible rather than
              something the customer has to remember. A drop after a swap is styled as
              information, not as an alarm — it is a decision they made, not a fault. */}
          {result.trend?.note ? (
            <p
              className={
                result.trend.direction === "regressed" && !result.trend.model_changed
                  ? "rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-ink"
                  : "text-xs text-muted"
              }
            >
              {result.trend.note}
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

// The starter check, always its own block. These are OUR cases, so the label leads with what it is
// not: a customer must never read this as a score about their estate.
function StarterBlock({ s }: { s: Starter }) {
  const total = s.cases ?? 0;
  const passed = s.passed ?? 0;
  return (
    <div className="rounded-xl border border-border bg-surface-2/40 px-4 py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Starter check</h3>
        <div className="text-sm font-semibold text-ink">
          {passed}
          <span className="font-normal text-muted">/{total}</span>
        </div>
      </div>
      <p className="mt-1 text-xs text-muted">{s.what_it_is}</p>
      {s.balance ? (
        <p className="mt-1 text-xs text-muted">
          {s.balance.keep} to keep, {s.balance.suppress} to suppress.
        </p>
      ) : null}
      {s.unanswered ? (
        <p className="mt-1 text-xs text-muted">
          {s.unanswered} unanswered, counted as missed
          {s.unanswered_reason ? ` — ${s.unanswered_reason}` : null}
        </p>
      ) : null}
    </div>
  );
}
