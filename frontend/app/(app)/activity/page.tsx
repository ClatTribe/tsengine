import { Radio, CheckCircle2, XCircle, ShieldQuestion, Wrench, TrendingDown } from "lucide-react";
import { api } from "@/lib/api";
import { ActivityTimeline, type ActivityEvent } from "@/components/activity/activity-timeline";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

// A friendly day bucket relative to the server's "now" (force-dynamic → recomputed each
// render, including the SSE-triggered refresh). Returned as a string prop so the client
// component never recomputes dates → no hydration drift.
function dayLabel(iso: string, now: Date): string {
  const d = new Date(iso);
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((startOf(now) - startOf(d)) / 86_400_000);
  if (diff <= 0) return "Today";
  if (diff === 1) return "Yesterday";
  if (diff < 7) return `${diff} days ago`;
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: now.getFullYear() === d.getFullYear() ? undefined : "numeric" });
}

// withApprover names the human who passed a change through the HITL gate.
//
// The gate is the product's central invariant — the only write path is reached AFTER a human decides,
// and every decision is signed into the ledger. WHO decided is therefore the accountability record,
// and it was stored, signed, and shown nowhere: an applied change to a customer's cloud appeared with
// no sign of who authorised it. Auto-applied tier-0/1 actions have no approver and correctly say so
// by omission rather than by inventing one.
function withApprover(meta: string | undefined, approver?: string): string {
  const base = meta || "";
  if (!approver) return base;
  const who = `approved by ${approver}`;
  return base ? `${base} · ${who}` : who;
}

export default async function ActivityPage() {
  const [incidents, engagements, approvals, actions, trend] = await Promise.all([
    api.incidents("all"),
    api.engagements(),
    api.approvals(),
    api.actions(),
    api.exposureTrend(),
  ]);

  const events: ActivityEvent[] = [];

  // incidents → detected (open) / resolved
  for (const i of incidents) {
    if (i.status === "resolved" && i.resolved_at) {
      events.push({ id: `inc-r-${i.id}`, at: i.resolved_at, day: "", kind: "resolved", title: i.title, meta: i.rule_id, severity: i.severity, href: "/incidents" });
    } else if (i.opened_at) {
      events.push({ id: `inc-d-${i.id}`, at: i.opened_at, day: "", kind: "detected", title: i.title, meta: i.rule_id, severity: i.severity, href: i.finding_id ? `/findings/${i.finding_id}` : "/incidents" });
    }
  }
  // engagements → scanned
  for (const e of engagements) {
    if (e.completed_at) events.push({ id: `eng-${e.id}`, at: e.completed_at, day: "", kind: "scanned", title: "Scanned an asset", meta: e.trigger });
  }
  // pending approvals → a fix queued for the human
  for (const a of approvals) {
    if (a.created_at) events.push({ id: `act-${a.id}`, at: a.created_at, day: "", kind: "queued", title: a.title || "Fix proposed", meta: `${a.kind} · tier ${a.tier}`, href: "/inbox" });
  }
  // applied fixes that were RE-TESTED → confirmed fixed, or still-present (the fix didn't work). The
  // KF#4 answer: we don't just propose a fix, we prove it closed the finding (or flag that it didn't).
  for (const a of actions.actions) {
    const v = a.verification;
    if (!v?.verified_at) continue;
    if (v.status === "fixed") {
      events.push({ id: `fix-${a.id}`, at: v.verified_at, day: "", kind: "verified", title: `Fix verified — ${a.title || a.kind}`, meta: withApprover(v.evidence, a.approver), href: "/inbox" });
    } else {
      events.push({ id: `fix-${a.id}`, at: v.verified_at, day: "", kind: "regressed", title: `Fix did not close — ${a.title || a.kind}`, meta: withApprover(v.evidence, a.approver), href: "/inbox" });
    }
  }

  // Actions whose delivery FAILED. These sit at "approved" so they are not lost, which also means
  // they are invisible: not in the inbox (nothing left to approve) and not a verified fix. Without
  // this the customer's ticket simply never arrives and nothing anywhere says why.
  for (const a of actions.actions) {
    if (!a.delivery_error) continue;
    events.push({
      id: `err-${a.id}`,
      at: a.decided_at || a.created_at || "",
      day: "",
      kind: "failed",
      title: `Could not deliver — ${a.title || a.kind}`,
      meta: withApprover(a.delivery_error, a.approver),
      href: "/inbox",
    });
  }

  events.sort((x, y) => new Date(y.at).getTime() - new Date(x.at).getTime());
  const now = new Date();
  for (const ev of events) ev.day = dayLabel(ev.at, now);

  return (
    <div className="space-y-5">
      <PageIntro
        icon={Radio}
        title="Activity"
        description="A live, plain-English log of everything the agent has done for you — every weakness it found, every fix it queued, and every scan it ran. Watch it work in real time."
      />
      {actions.failed_delivery > 0 && (
        <div className="card flex items-center gap-3 border-high/30 px-4 py-3 text-sm">
          <XCircle className="h-4 w-4 shrink-0 text-high" />
          <span className="text-muted">
            <span className="font-medium text-high">{actions.failed_delivery}</span>{" "}
            {actions.failed_delivery === 1 ? "approved fix" : "approved fixes"} could not be delivered — the
            integration rejected them. They are approved but never reached their destination; check the
            connection and re-approve.
          </span>
        </div>
      )}
      {actions.verified > 0 && (
        <div className="card flex items-center gap-3 px-4 py-3 text-sm">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-pulse" />
          <span className="text-muted">
            <span className="font-medium text-ink">{actions.confirmed_fix} of {actions.verified}</span> applied fixes were
            re-tested and <span className="font-medium text-ink">confirmed closed</span>
            {actions.still_present > 0 && (
              <> — <span className="font-medium text-high">{actions.still_present}</span> did not close and stay open</>
            )}
            . We don&apos;t just propose fixes, we prove they worked.
          </span>
        </div>
      )}
      {actions.awaiting_proof > 0 && (
        <div className="card flex items-start gap-3 px-4 py-3 text-sm">
          <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-medium" />
          <span className="text-muted">
            <span className="font-medium text-ink">{actions.awaiting_proof}</span>{" "}
            {actions.awaiting_proof === 1 ? "fix was" : "fixes were"} found gone on re-scan but{" "}
            <span className="font-medium text-ink">not counted as confirmed</span> — a clean re-scan for
            {" "}{actions.awaiting_proof === 1 ? "that class" : "those classes"} has been contradicted by a
            live exploit before, so it awaits a re-attack.
            {actions.distrusted_classes && actions.distrusted_classes.length > 0 && (
              <span className="mt-2 block text-xs text-subtle">
                Where our own evidence has failed:{" "}
                {actions.distrusted_classes.map((c) => (
                  <span key={c.class} className="mr-2 inline-block font-mono">
                    {c.class} ({c.contradicted}/{c.clean_rescans})
                  </span>
                ))}
              </span>
            )}
          </span>
        </div>
      )}
      {actions.weakest_remediations && actions.weakest_remediations.length > 0 && (
        <div className="card flex items-start gap-3 px-4 py-3 text-sm">
          <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-medium" />
          <span className="text-muted">
            <span className="font-medium text-ink">Fixes that keep not working.</span> These
            remediations were applied and the finding was still there afterwards — the runbook is
            wrong, not the scan.
            <span className="mt-2 block space-y-1 text-xs">
              {actions.weakest_remediations.map((w) => (
                <span key={`${w.class}:${w.remediation_type}`} className="block">
                  <span className="font-mono text-subtle">{w.remediation_type}</span> on{" "}
                  <span className="font-mono text-subtle">{w.class}</span> — closed {w.closed} of{" "}
                  {w.closed + w.not_closed}
                </span>
              ))}
            </span>
          </span>
        </div>
      )}
      {trend.points.length > 0 && (
        <div className="card px-4 py-3 text-sm">
          <div className="flex items-center gap-2">
            <TrendingDown className="h-4 w-4 shrink-0 text-muted" />
            <span className="font-medium text-ink">Is exposure going down?</span>
          </div>
          <div className="mt-2 space-y-1 text-xs">
            {trend.points.slice(-8).map((p) => (
              <div key={p.day} className="flex gap-3 text-muted">
                <span className="font-mono text-subtle">{p.day}</span>
                <span>+{p.opened} opened</span>
                <span>&minus;{p.closed} stopped appearing</span>
                {p.unscored > 0 && <span className="text-medium">{p.unscored} unmeasured</span>}
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted">
            <span className="font-medium text-ink">{trend.confirmed_fixed}</span> were confirmed
            fixed by a re-test.{" "}
            {trend.mixed && (
              <span className="text-medium">
                This series mixes {trend.scopes_included?.length} scopes, which census different
                things and are not directly comparable.{" "}
              </span>
            )}
            <span className="mt-1 block text-subtle">{trend.caveat}</span>
          </p>
        </div>
      )}
      <ActivityTimeline events={events} />
    </div>
  );
}
