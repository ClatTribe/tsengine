"use client";

import { useState, useTransition } from "react";
import { Loader2, Check, Gauge } from "lucide-react";
import { setAIMode } from "@/app/(app)/settings/actions";
import type { AIModeResponse } from "@/lib/types";

// AIModeControl is where the customer decides HOW MUCH AI runs, and caps what it can cost.
//
// It exists because "all of it or none of it" loses the customer who would have said yes in six
// weeks. At this stage the reasons to say "not yet" are ordinary: predictable cost, a trust ramp
// (watch the deterministic engine for a month before letting a model open PRs against your repo), or
// a policy that your source only goes to a model you control.
//
// Two things it must never do, both of which the server already enforces and this surface mirrors:
//
//   - Hide WHY something is off. Every state carries a reason, and an unavailable option says how to
//     enable it. A control that refuses silently sends someone looking in the wrong place.
//   - Let a mode change quietly clear a budget. The ceiling is only sent when it was edited, so
//     switching modes cannot produce a surprise bill later.
export function AIModeControl({ initial }: { initial: AIModeResponse }) {
  const [state, setState] = useState(initial);
  const [budget, setBudget] = useState(
    initial.budget_usd > 0 ? String(initial.budget_usd) : "",
  );
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function save(mode: string, withBudget: boolean) {
    setErr("");
    setSaved(false);
    let b: number | undefined;
    if (withBudget) {
      const trimmed = budget.trim();
      // Empty means "no ceiling" — an explicit 0, not "leave it alone". Leaving it alone is what
      // happens when the budget field was not touched at all.
      b = trimmed === "" ? 0 : Number(trimmed);
      if (Number.isNaN(b) || b < 0) {
        setErr("Enter a monthly budget in dollars, or leave it blank for no ceiling.");
        return;
      }
    }
    start(async () => {
      try {
        setState(await setAIMode(mode, b));
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Could not save.");
      }
    });
  }

  return (
    <div className="space-y-4">
      {/* What is running right now, and why. The reason is the server's — it knows whether the cause
          is the plan, this choice, the kill-switch, or an exhausted budget. */}
      <p className="text-sm leading-relaxed text-muted">{state.reason}</p>

      <div className="space-y-2">
        {state.choices.map((c) => {
          const active = state.mode === c.mode;
          return (
            <button
              key={c.mode}
              type="button"
              disabled={!c.available || pending}
              onClick={() => save(c.mode, false)}
              className={`w-full rounded-xl border p-3.5 text-left transition ${
                active ? "border-accent/50 bg-accent-soft/20" : "border-border hover:bg-surface-2"
              } ${!c.available ? "cursor-not-allowed opacity-60" : ""}`}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-medium text-ink">{c.label}</span>
                <span className="shrink-0 text-[11px] text-muted">{c.cost}</span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-muted">{c.detail}</p>
              {/* An unavailable option explains itself rather than just greying out. */}
              {!c.available && c.why && (
                <p className="mt-1.5 text-xs leading-relaxed text-warning">{c.why}</p>
              )}
            </button>
          );
        })}
      </div>

      {/* The money. Spend alone is a number you read; the remainder is a number you can plan with. */}
      <div className="rounded-xl border border-border p-3.5">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
          <Gauge className="h-3.5 w-3.5" /> This month
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
          <span className="text-ink">
            ${state.spend_usd.toFixed(2)} <span className="text-muted">spent</span>
          </span>
          <span className="text-muted">
            {state.runs} {state.runs === 1 ? "run" : "runs"}
          </span>
          {state.budget_usd > 0 && (
            <span className="text-ink">
              ${state.remaining_usd.toFixed(2)} <span className="text-muted">left of ${state.budget_usd.toFixed(2)}</span>
            </span>
          )}
          {state.using_own_key && (
            <span className="text-xs text-muted">billed to your own LLM key</span>
          )}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <label htmlFor="ai-budget" className="text-xs text-muted">
            Monthly ceiling ($)
          </label>
          <input
            id="ai-budget"
            value={budget}
            onChange={(e) => setBudget(e.target.value)}
            placeholder="no ceiling"
            inputMode="decimal"
            className="w-28 rounded-lg border border-border bg-bg px-2.5 py-1.5 text-sm text-ink outline-none focus:border-accent"
          />
          <button
            type="button"
            disabled={pending}
            onClick={() => save(state.mode, true)}
            className="rounded-lg border border-border px-3 py-1.5 text-sm text-ink transition hover:bg-surface-2 disabled:opacity-60"
          >
            {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save ceiling"}
          </button>
          {saved && !pending && (
            <span className="flex items-center gap-1 text-xs text-pulse">
              <Check className="h-3.5 w-3.5" /> Saved
            </span>
          )}
        </div>
        <p className="mt-2 text-xs leading-relaxed text-muted">
          When the ceiling is reached the agents pause and we say so — deterministic scanning keeps
          running. We never quietly return thinner results, because &ldquo;out of budget&rdquo; and
          &ldquo;nothing found&rdquo; should never look the same.
        </p>
      </div>

      {err && <p className="text-sm text-danger">{err}</p>}
    </div>
  );
}
