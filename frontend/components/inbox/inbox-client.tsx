"use client";

import { useCallback, useEffect, useOptimistic, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Check, X, GitPullRequest, Settings2, Ticket, ShieldQuestion, Loader2, FileWarning, PenLine } from "lucide-react";
import type { Action, Finding } from "@/lib/types";
import { decideAction } from "@/app/(app)/inbox/actions";
import { SeverityBadge } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

const KIND_META: Record<string, { icon: typeof Check; label: string }> = {
  open_pr: { icon: GitPullRequest, label: "Open pull request" },
  apply_config: { icon: Settings2, label: "Apply config change" },
  file_ticket: { icon: Ticket, label: "File a ticket" },
  draft_notification: { icon: FileWarning, label: "Breach disclosure draft" },
};

function payloadSummary(a: Action): string | undefined {
  const p = a.payload ?? {};
  return (p.summary as string) || (p.draft as string) || (p.runbook as string) || (p.body as string) || (p.remediation as string) || undefined;
}

// A containment action is a file_ticket carrying remediation_type=containment — label it as
// such (it's a gated "stop the bleeding" recommendation, not a generic ticket).
function metaFor(a: Action): { icon: typeof Check; label: string } {
  if (a.payload?.remediation_type === "containment") return { icon: ShieldQuestion, label: "Containment — approve to act" };
  return KIND_META[a.kind] ?? { icon: ShieldQuestion, label: a.kind };
}

// Tier-3 (irreversible/legal — e.g. a breach disclosure) requires a named human signature;
// it can never auto-apply, and "approving" it means signing it.
function needsSignature(a: Action): boolean {
  return a.tier >= 3;
}

// tierMeaning translates the gate tier into plain English for a non-security SMB owner — what the action
// is, whether it can be undone, and WHY it's in their queue instead of auto-handled. This is the "SMB
// context" the raw "tier N" jargon didn't give. Mirrors platform.GateTier(2)/TierIrreversible(3).
function tierMeaning(tier: number): { label: string; reversible: boolean; why: string } {
  if (tier >= 3) {
    return {
      label: "Irreversible or legal",
      reversible: false,
      why: "It can't be undone (or it's a legal/customer communication), so it can never happen without a person signing off.",
    };
  }
  if (tier === 2) {
    return {
      label: "Reversible change",
      reversible: true,
      why: "It changes a real configuration. You can roll it back, but it's consequential enough that we hold it for your approval first.",
    };
  }
  return {
    label: "Low-risk & reversible",
    reversible: true,
    why: "Low-risk and easily undone — here for your awareness. Actions like this normally apply automatically within the agent's safe limits.",
  };
}

export function InboxClient({ actions, findings }: { actions: Action[]; findings: Record<string, Finding> }) {
  const [items, removeOptimistic] = useOptimistic(actions, (state, id: string) => state.filter((a) => a.id !== id));
  const [sel, setSel] = useState(0);
  const [pending, startTransition] = useTransition();

  const router = useRouter();
  const inFlight = useRef<Set<string>>(new Set());
  const decide = useCallback(
    (id: string, approve: boolean) => {
      // Guard against a re-entrant decision on the same action (a rapid double-click or a
      // click racing the keyboard shortcut) firing two POSTs — the second lands as a spurious
      // "already decided" 400. One decision per action stays in flight at a time.
      if (inFlight.current.has(id)) return;
      inFlight.current.add(id);
      startTransition(async () => {
        removeOptimistic(id);
        try {
          await decideAction(id, approve);
        } catch {
          // The decision can still fail benignly — the action was already decided (another
          // operator/Slack got there first) or the API blipped. Reconcile the optimistic
          // removal by refetching instead of throwing to the error boundary, which would nuke
          // the whole inbox to "Something went sideways".
          router.refresh();
        } finally {
          inFlight.current.delete(id);
        }
      });
    },
    [removeOptimistic, router],
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
            const meta = metaFor(a);
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
                    <span className={cn("text-[11px]", a.tier >= 3 ? "text-critical" : "text-faint")}>
                      {a.tier >= 3 ? "needs signature" : a.tier === 2 ? "reversible" : "low-risk"}
                    </span>
                    {a.finding_ids && a.finding_ids.length > 1 && (
                      <span className="rounded-full bg-accent-soft px-1.5 py-0.5 text-[10px] font-medium text-accent">
                        bulk · fixes {a.finding_ids.length}
                      </span>
                    )}
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
  const meta = metaFor(action);
  const Icon = meta.icon;
  const summary = payloadSummary(action);
  const target = action.payload?.target as string | undefined;
  const sign = needsSignature(action);

  return (
    <>
      <div className="flex items-start gap-3 border-b border-border p-5">
        <div className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-lg", sign ? "bg-critical/10 text-critical" : "bg-accent-soft text-accent")}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">{action.title ?? meta.label}</div>
          <div className="mono mt-0.5 text-xs text-faint">
            {meta.label} · tier {action.tier} · {action.id}
          </div>
        </div>
        {sign && (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[11px] font-medium text-critical ring-1 ring-critical/30">
            <PenLine className="h-3 w-3" /> needs your signature
          </span>
        )}
      </div>

      {sign && (
        <div className="border-b border-critical/20 bg-critical/5 px-5 py-2.5 text-xs text-critical">
          Irreversible / legal action. The agent prepared this draft — it cannot send it. Review and edit it,
          then sign to file it; reject to discard. Nothing is sent until a person signs.
        </div>
      )}

      {/* Plain-English "what this means for you" — so a non-security owner understands WHY it's in their
          queue and whether it can be undone, instead of decoding "tier N". Tier-3 has its own banner above. */}
      {!sign && (() => {
        const m = tierMeaning(action.tier);
        return (
          <div className="border-b border-border bg-surface-2/50 px-5 py-2.5 text-xs">
            <span className={cn("font-medium", m.reversible ? "text-ink" : "text-critical")}>{m.label}.</span>{" "}
            <span className="text-muted">{m.why}</span>
          </div>
        );
      })()}

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

        {/* What it will do / the draft to review */}
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">{sign ? "Draft to review & sign" : "What it will do"}</div>
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
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : sign ? <PenLine className="h-4 w-4" /> : <Check className="h-4 w-4" />}
          {sign ? "Sign & file" : "Approve"} <kbd className="mono ml-1 rounded border border-pulse/30 px-1 text-[10px]">a</kbd>
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
