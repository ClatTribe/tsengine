"use client";

import Link from "next/link";

import { useCallback, useEffect, useOptimistic, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Check, X, GitPullRequest, Settings2, Ticket, ShieldQuestion, Loader2, FileWarning, PenLine, MessageSquare, AlertTriangle, History } from "lucide-react";
import type { Action, Finding } from "@/lib/types";
import { decideAction, requestChangesAction } from "@/app/(app)/inbox/actions";
import { SeverityBadge } from "@/components/ui/primitives";
import { ConfidencePill } from "@/components/findings/confidence-pill";
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
  // Why the last decision did not do what it looked like it did. Held at list level, not on the
  // row, because a failed apply removes the row from the queue — the explanation has to outlive it.
  const [notice, setNotice] = useState<string | null>(null);

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
          const res = await decideAction(id, approve);
          // A failed APPLY is not a benign blip: the desk leaves the action approved-but-
          // un-applied and it drops out of the pending queue, so staying silent here shows the
          // customer exactly what success looks like while nothing was fixed. Say what happened.
          if (res?.error) {
            setNotice(res.error);
            router.refresh();
          } else {
            setNotice(null);
          }
        } catch {
          // A thrown error (rather than a returned one) is the transport failing. Reconcile the
          // optimistic removal by refetching instead of throwing to the error boundary, which
          // would nuke the whole inbox to "Something went sideways".
          setNotice("That decision did not go through — the list has been refreshed.");
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
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {notice ? (
        // A decision that did not land. Kept visible until dismissed: the row it refers to is
        // already gone, so this is the only place the customer can learn the fix did not apply.
        <div className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
          <div className="min-w-0 flex-1">
            <div className="font-medium text-ink">That approval did not complete</div>
            <p className="mt-0.5 break-words text-muted">{notice}</p>
            <p className="mt-1 text-xs text-muted">
              Nothing was applied. The action is recorded with this reason — see Activity for the full trail.
            </p>
          </div>
          <button
            onClick={() => setNotice(null)}
            className="shrink-0 rounded px-2 py-0.5 text-xs text-muted transition hover:text-ink"
          >
            Dismiss
          </button>
        </div>
      ) : null}
      <div className="flex min-h-0 flex-1 gap-4">
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

      {/* A known blocker, surfaced BEFORE the decision. Approving this would record the verdict but
          change nothing, so say it while the choice is still open rather than after the click. */}
      {action.apply_blocked && (
        <div className="flex items-start gap-2 border-b border-amber-500/25 bg-amber-500/5 px-5 py-2.5 text-xs">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
          <div className="min-w-0">
            <span className="font-medium text-ink">Approving this will not apply it yet.</span>{" "}
            <span className="text-muted">{action.apply_blocked}</span>
            <div className="mt-0.5 text-muted">
              Your approval is still recorded — but connect the write path first if you want the fix to land.
            </div>
          </div>
        </div>
      )}

      {/* The remediation's measured track record, from this tenant's OWN verified history (ADR 0025
          F2). "Closed 8 of 10" and "reopened 5 of 8" are different decisions for the person about to
          approve this, and before this they read identically. Absent when there is not enough
          history — silence means "not known", never "this will work". */}
      {action.fix_efficacy?.muted && (
        <div className="flex items-start gap-2 border-b border-line px-5 py-2.5 text-xs">
          <History className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
          <div className="min-w-0 text-muted">
            <span className="font-medium text-ink">This fix has a history, but we cannot score it.</span>{" "}
            {action.fix_efficacy.unproven} previous {action.fix_efficacy.unproven === 1 ? "application" : "applications"}
            {" "}could not be confirmed either way, so there is not enough settled evidence to say whether
            this kind of fix works. That is not the same as it having no track record.
          </div>
        </div>
      )}
      {action.fix_efficacy && !action.fix_efficacy.muted &&
        (action.fix_efficacy.closed + action.fix_efficacy.not_closed) > 0 && (
        <div className="flex items-start gap-2 border-b border-line px-5 py-2.5 text-xs">
          <History className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
          <div className="min-w-0 text-muted">
            <span className="font-medium text-ink">
              This kind of fix has closed this kind of finding {action.fix_efficacy.closed} of{" "}
              {action.fix_efficacy.closed + action.fix_efficacy.not_closed} times
            </span>{" "}
            on your estate.
            {action.fix_efficacy.not_closed > 0 && (
              <> {action.fix_efficacy.not_closed} did not close and had to be reopened.</>
            )}
            {action.fix_efficacy.unproven ? (
              <div className="mt-0.5">
                A further {action.fix_efficacy.unproven} could not be confirmed either way, so they are
                excluded from that count rather than counted as successes.
              </div>
            ) : null}
          </div>
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
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                {/* HOW SURE ARE WE. The pill is on every other agent-output surface and was missing from
                    the ONE place a human authorises a change. Approving a fix for a single-tool pattern
                    match is a different decision from approving one for a proven exploit, and without
                    this they look identical. */}
                <ConfidencePill verification={finding.verification_status} confidence={finding.confidence} />
                <span className="text-sm">{finding.title}</span>
              </div>
              {finding.endpoint && <div className="mono mt-1.5 truncate text-xs text-faint">{finding.endpoint}</div>}
              {finding.description && <p className="mt-2 text-sm text-muted">{finding.description}</p>}
              {finding.verification_status && finding.verification_status !== "verified" && (
                <p className="mt-2 border-t border-border pt-2 text-xs leading-relaxed text-muted">
                  This finding is <span className="font-medium text-ink">not exploit-proven</span> — a tool
                  matched a pattern. Approving fixes it either way; if you would rather know first, the AI
                  Pentester can try to settle it from the{" "}
                  <Link href="/pentest" className="text-accent hover:underline">proof queue</Link>.
                </p>
              )}
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

        {/* The code itself. Approving a change you cannot see is a signature, not a review — so when
            the action carries a diff, it leads. */}
        {action.diff && <DiffView diff={action.diff} />}

        {/* A returned proposal shows what was asked for, so the reviewer sees the thread rather than
            an unexplained second attempt. */}
        {action.feedback && (
          <section>
            <div className="mb-2 text-xs uppercase tracking-wider text-muted">Changes requested</div>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <p className="text-sm text-ink">{action.feedback}</p>
              {action.reviewed_by && (
                <div className="mt-1.5 text-xs text-faint">— {action.reviewed_by}</div>
              )}
            </div>
          </section>
        )}
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
        {/* The verdict a senior engineer reaches for most often. Without it, spotting one wrong line
            means destroying a proposal that was 90% right — which trains rubber-stamping. */}
        <RequestChangesButton actionId={action.id} disabled={pending} />
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

// DiffView renders the unified diff the action would apply.
//
// This is the difference between a review and a signature. The colouring is deliberately plain —
// added/removed/context — because a reviewer scanning for one wrong line needs contrast, not syntax
// highlighting. Long diffs scroll inside their own box so the panel never grows unbounded.
function DiffView({ diff }: { diff: string }) {
  const lines = diff.split("\n");
  return (
    <section>
      <div className="mb-2 text-xs uppercase tracking-wider text-muted">The change</div>
      <div className="max-h-80 overflow-auto rounded-lg border border-border bg-bg">
        <pre className="mono min-w-max p-3 text-[11px] leading-relaxed">
          {lines.map((l, i) => {
            const kind =
              l.startsWith("+++") || l.startsWith("---")
                ? "text-faint"
                : l.startsWith("@@")
                  ? "text-accent"
                  : l.startsWith("+")
                    ? "bg-pulse/10 text-pulse"
                    : l.startsWith("-")
                      ? "bg-critical/10 text-critical"
                      : "text-muted";
            return (
              <div key={i} className={cn("px-1", kind)}>
                {l || " "}
              </div>
            );
          })}
        </pre>
      </div>
    </section>
  );
}

// RequestChangesButton opens a note box and sends the proposal BACK — it is not applied and not
// closed, so the agent can re-propose against the feedback.
function RequestChangesButton({ actionId, disabled }: { actionId: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!open) {
    return (
      <button
        disabled={disabled}
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 rounded-lg bg-amber-500/10 px-3.5 py-2 text-sm font-medium text-amber-600 transition hover:bg-amber-500/20 disabled:opacity-50 dark:text-amber-400"
      >
        <MessageSquare className="h-4 w-4" />
        Request changes
      </button>
    );
  }
  return (
    <div className="flex flex-1 items-start gap-2">
      <div className="flex-1">
        <textarea
          autoFocus
          rows={2}
          value={note}
          onChange={(e) => {
            setNote(e.target.value);
            setErr(null);
          }}
          placeholder="What should change? e.g. parameterise the ORDER BY clause too"
          className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm outline-none focus:border-accent/50"
        />
        {err && <div className="mt-1 text-xs text-critical">{err}</div>}
      </div>
      <button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          const res = await requestChangesAction(actionId, note);
          setBusy(false);
          if (res?.error) {
            setErr(res.error);
            return;
          }
          setOpen(false);
          setNote("");
        }}
        className="flex items-center gap-2 rounded-lg bg-amber-500/15 px-3.5 py-2 text-sm font-medium text-amber-600 transition hover:bg-amber-500/25 disabled:opacity-50 dark:text-amber-400"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <MessageSquare className="h-4 w-4" />}
        Send back
      </button>
      <button
        onClick={() => {
          setOpen(false);
          setErr(null);
        }}
        className="rounded-lg px-3 py-2 text-sm text-muted transition hover:text-ink"
      >
        Cancel
      </button>
    </div>
  );
}
