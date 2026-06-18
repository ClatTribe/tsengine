"use client";

import { useCallback, useEffect, useOptimistic, useState, useTransition } from "react";
import { Check, X, GitPullRequest, Settings2, Ticket, ShieldQuestion, Loader2 } from "lucide-react";
import type { Action, Finding } from "@/lib/types";
import { decideAction } from "@/app/(app)/inbox/actions";
import { SeverityBadge } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const KIND_META: Record<string, { icon: typeof Check; label: string }> = {
  open_pr: { icon: GitPullRequest, label: "Open pull request" },
  apply_config: { icon: Settings2, label: "Apply config change" },
  file_ticket: { icon: Ticket, label: "File a ticket" },
};

function payloadSummary(a: Action): string | undefined {
  const p = a.payload ?? {};
  return (p.summary as string) || (p.body as string) || (p.remediation as string) || undefined;
}

export function InboxClient({ actions, findings }: { actions: Action[]; findings: Record<string, Finding> }) {
  const [items, removeOptimistic] = useOptimistic(actions, (state, id: string) => state.filter((a) => a.id !== id));
  const [sel, setSel] = useState(0);
  const [pending, startTransition] = useTransition();

  const decide = useCallback(
    (id: string, approve: boolean) => {
      startTransition(async () => {
        removeOptimistic(id);
        await decideAction(id, approve);
      });
    },
    [removeOptimistic],
  );

  useEffect(() => {
    setSel((s) => Math.min(s, Math.max(0, items.length - 1)));
  }, [items.length]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const cur = items[sel];
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setSel((s) => Math.min(items.length - 1, s + 1));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setSel((s) => Math.max(0, s - 1));
      } else if (e.key === "a" && cur) {
        e.preventDefault();
        decide(cur.id, true);
      } else if (e.key === "r" && cur) {
        e.preventDefault();
        decide(cur.id, false);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [items, sel, decide]);

  if (items.length === 0) {
    return (
      <div className="card flex flex-col items-center gap-3 p-12 text-center animate-fade-rise">
        <div className="grid h-12 w-12 place-items-center rounded-full bg-pulse/10 text-pulse">
          <Check className="h-6 w-6" />
        </div>
        <div className="text-sm font-medium">Inbox zero</div>
        <div className="max-w-xs text-sm text-muted">
          Nothing needs you. The agent is auto-handling everything within its safe tiers.
        </div>
      </div>
    );
  }

  const selected = items[Math.min(sel, items.length - 1)];

  return (
    <div className="flex h-[calc(100vh-7rem)] gap-4">
      {/* List */}
      <div className="w-80 shrink-0 overflow-y-auto pr-1">
        <ul className="space-y-1.5">
          {items.map((a, i) => {
            const meta = KIND_META[a.kind] ?? { icon: ShieldQuestion, label: a.kind };
            const Icon = meta.icon;
            const f = findings[a.finding_id];
            return (
              <li key={a.id}>
                <button
                  onClick={() => setSel(i)}
                  className={cn(
                    "w-full rounded-lg border px-3 py-2.5 text-left transition",
                    i === sel ? "border-accent/50 bg-surface-2 shadow-glow" : "border-border bg-surface hover:border-border-strong",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Icon className="h-3.5 w-3.5 shrink-0 text-accent" />
                    <span className="truncate text-sm">{a.title ?? meta.label}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    {f && <SeverityBadge severity={f.severity} className="scale-90" />}
                    <span className="mono text-[11px] text-faint">tier {a.tier}</span>
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      {/* Detail */}
      <div className="card flex min-w-0 flex-1 flex-col p-0 animate-fade-rise">
        {selected && <DetailPane action={selected} finding={findings[selected.finding_id]} pending={pending} onDecide={decide} />}
      </div>
    </div>
  );
}

function DetailPane({
  action,
  finding,
  pending,
  onDecide,
}: {
  action: Action;
  finding?: Finding;
  pending: boolean;
  onDecide: (id: string, approve: boolean) => void;
}) {
  const meta = KIND_META[action.kind] ?? { icon: ShieldQuestion, label: action.kind };
  const Icon = meta.icon;
  const summary = payloadSummary(action);
  const target = action.payload?.target as string | undefined;

  return (
    <>
      <div className="flex items-start gap-3 border-b border-border p-5">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-medium">{action.title ?? meta.label}</div>
          <div className="mono mt-0.5 text-xs text-faint">
            {meta.label} · tier {action.tier} · {action.id}
          </div>
        </div>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto p-5">
        {/* Why — the citing finding */}
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Why the agent proposed this</div>
          {finding ? (
            <div className="rounded-lg border border-border bg-surface-2 p-3">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="text-sm">{finding.title}</span>
              </div>
              {finding.endpoint && <div className="mono mt-1.5 truncate text-xs text-faint">{finding.endpoint}</div>}
              {finding.description && <p className="mt-2 text-sm text-muted">{finding.description}</p>}
            </div>
          ) : (
            <div className="mono text-xs text-faint">finding {action.finding_id}</div>
          )}
        </section>

        {/* What it will do */}
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">What it will do</div>
          {target && (
            <div className="mb-2 text-sm">
              Target: <span className="mono rounded border border-border bg-surface-2 px-1.5 py-0.5">{target}</span>
            </div>
          )}
          {summary ? (
            <pre className="whitespace-pre-wrap rounded-lg border border-border bg-bg p-3 text-xs text-muted">{summary}</pre>
          ) : (
            <div className="text-sm text-faint">No additional detail provided.</div>
          )}
        </section>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 border-t border-border p-4">
        <button
          disabled={pending}
          onClick={() => onDecide(action.id, true)}
          className="flex items-center gap-2 rounded-lg bg-pulse/15 px-3.5 py-2 text-sm font-medium text-pulse transition hover:bg-pulse/25 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
          Approve <kbd className="mono ml-1 rounded border border-pulse/30 px-1 text-[10px]">a</kbd>
        </button>
        <button
          disabled={pending}
          onClick={() => onDecide(action.id, false)}
          className="flex items-center gap-2 rounded-lg bg-critical/10 px-3.5 py-2 text-sm font-medium text-critical transition hover:bg-critical/20 disabled:opacity-50"
        >
          <X className="h-4 w-4" />
          Reject <kbd className="mono ml-1 rounded border border-critical/30 px-1 text-[10px]">r</kbd>
        </button>
        <div className="ml-auto text-[11px] text-faint">
          <kbd className="mono rounded border border-border px-1">j</kbd>/<kbd className="mono rounded border border-border px-1">k</kbd> navigate ·
          every decision is signed into the ledger
        </div>
      </div>
    </>
  );
}
