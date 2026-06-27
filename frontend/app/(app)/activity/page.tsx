import { Radio, CheckCircle2 } from "lucide-react";
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

export default async function ActivityPage() {
  const [incidents, engagements, approvals, actions] = await Promise.all([
    api.incidents("all"),
    api.engagements(),
    api.approvals(),
    api.actions(),
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
      events.push({ id: `fix-${a.id}`, at: v.verified_at, day: "", kind: "verified", title: `Fix verified — ${a.title || a.kind}`, meta: v.evidence, href: "/inbox" });
    } else {
      events.push({ id: `fix-${a.id}`, at: v.verified_at, day: "", kind: "regressed", title: `Fix did not close — ${a.title || a.kind}`, meta: v.evidence, href: "/inbox" });
    }
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
      <ActivityTimeline events={events} />
    </div>
  );
}
