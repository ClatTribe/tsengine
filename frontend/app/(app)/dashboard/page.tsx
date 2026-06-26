import Link from "next/link";
import {
  ArrowRight, ScanLine, ShieldAlert, ShieldCheck, Wrench, Inbox as InboxIcon,
  Boxes, Radar, Plug, CheckCircle2, Spline, Layers,
} from "lucide-react";
import { api, FRAMEWORK_LABEL } from "@/lib/api";
import { riskRating, severityCounts, sevRank, timeAgo } from "@/lib/utils";
import { categoryBreakdown } from "@/lib/categories";
import { Card, SectionTitle, SeverityBadge, Empty } from "@/components/ui/primitives";
import { FirstRun } from "@/components/onboarding/first-run";

export const dynamic = "force-dynamic";

// Honest verdicts (no-false-compliant, extended to the risk rating): a clean scan means "nothing flagged",
// NOT "you're protected" — absence of findings is not a guarantee of security. Only the cautionary verdicts
// make a strong claim, because there it's warranted.
const VERDICT: Record<string, string> = {
  Clear: "Nothing flagged right now",
  Low: "Low risk — minor items to review",
  Medium: "A few things to review",
  High: "Some issues need your attention",
  Critical: "Action needed now",
};
const RISK_TONE: Record<string, string> = {
  Critical: "text-critical",
  High: "text-high",
  Medium: "text-medium",
  Low: "text-low",
  Clear: "text-pulse",
};
const RISK_RING: Record<string, string> = {
  Critical: "bg-critical/10 text-critical",
  High: "bg-high/10 text-high",
  Medium: "bg-medium/10 text-medium",
  Low: "bg-low/10 text-low",
  Clear: "bg-pulse-soft text-pulse",
};

type Event = { at: string; kind: "detected" | "resolved" | "scanned"; title: string; meta?: string };

export default async function OverviewPage() {
  const connections = await api.connections();
  if (connections.length === 0) return <FirstRun />;

  // One concurrent wave for the whole dashboard. Compliance posture for every framework arrives
  // in a SINGLE batched call (postureSummary) instead of fanning out 14 per-framework requests,
  // and it rides in the same Promise.all as everything else.
  const [findings, incidents, approvals, engagements, assets, attackPaths, issuesResp, postureResp] = await Promise.all([
    api.findings(),
    api.incidents("all"),
    api.approvals(),
    api.engagements(),
    api.assets(),
    api.attackPaths(),
    api.issues(),
    api.postureSummary(),
  ]);

  const counts = severityCounts(findings);
  const byCategory = categoryBreakdown(findings);
  const risk = riskRating(counts);
  // Noise-reduction: how many duplicate findings the unified-issues layer collapsed.
  const merged = Math.max(0, issuesResp.raw_findings - issuesResp.count);
  const noisePct = issuesResp.raw_findings > 0 ? Math.round((merged / issuesResp.raw_findings) * 100) : 0;
  const protectedNow = risk === "Clear";

  const sub = protectedNow
    ? "TensorShield is monitoring your systems continuously — nothing needs you right now."
    : approvals.length > 0
      ? `TensorShield is on it — ${approvals.length} fix${approvals.length === 1 ? "" : "es"} prepared and waiting for your approval.`
      : "TensorShield is triaging these and will prepare fixes you can approve.";

  // Synthesize the agent activity feed.
  const events: Event[] = [];
  for (const i of incidents) {
    if (i.status === "resolved" && i.resolved_at) events.push({ at: i.resolved_at, kind: "resolved", title: i.title, meta: i.rule_id });
    else events.push({ at: i.opened_at, kind: "detected", title: i.title, meta: i.rule_id });
  }
  for (const e of engagements) if (e.completed_at) events.push({ at: e.completed_at, kind: "scanned", title: "Scanned an asset", meta: e.trigger });
  events.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());

  const frameworks = postureResp.frameworks;
  const resolvedCount = incidents.filter((i) => i.status === "resolved").length;

  return (
    <div className="space-y-6">
      {/* Posture hero — reassurance first */}
      <Card className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center">
        <div className="flex items-center gap-4">
          <div className={`grid h-16 w-16 shrink-0 place-items-center rounded-2xl ${RISK_RING[risk]}`}>
            {protectedNow ? <ShieldCheck className="h-8 w-8" /> : <ShieldAlert className="h-8 w-8" />}
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-faint">Your security posture</div>
            <div className={`mt-0.5 text-2xl font-semibold tracking-tight ${RISK_TONE[risk]}`}>{VERDICT[risk] ?? risk}</div>
            <p className="mt-1 max-w-md text-sm text-muted">{sub}</p>
          </div>
        </div>
        <div className="sm:ml-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full bg-pulse-soft px-2.5 py-1 text-xs font-medium text-pulse">
            <span className="pulse-dot" /> Monitoring 24/7
          </div>
          <div className="mt-3 flex gap-1.5">
            {(["critical", "high", "medium", "low"] as const).map((s) => (
              <div key={s} className="min-w-[3.25rem] rounded-xl border border-border bg-surface-2 px-2.5 py-1.5 text-center">
                <div className={`text-base font-semibold ${counts[s] ? RISK_TONE[s === "critical" ? "Critical" : s === "high" ? "High" : s === "medium" ? "Medium" : "Low"] : "text-faint"}`}>
                  {counts[s]}
                </div>
                <div className="text-[9px] uppercase tracking-wide text-faint">{s}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* Needs you */}
      {approvals.length > 0 && (
        <Link href="/inbox" className="block">
          <Card className="lift flex items-center gap-4 border-accent/40 bg-accent-soft/40 p-5 hover:border-accent/70">
            <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
              <InboxIcon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold">
                {approvals.length} fix{approvals.length > 1 ? "es" : ""} ready for your approval
              </div>
              <div className="text-xs text-muted">The agent prepared these and is holding for your decision — review in the Inbox.</div>
            </div>
            <ArrowRight className="ml-auto h-5 w-5 shrink-0 text-accent" />
          </Card>
        </Link>
      )}

      {/* What TensorShield is handling for you */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <HandledStat icon={Plug} n={connections.length} label="systems connected" />
        <HandledStat icon={Boxes} n={assets.length} label="assets monitored" />
        <HandledStat icon={ScanLine} n={engagements.length} label="scans run" />
        <HandledStat icon={Wrench} n={resolvedCount} label="issues resolved" tone="text-pulse" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Agent activity */}
        <div className="lg:col-span-2">
          <SectionTitle action={<span className="inline-flex items-center gap-1 text-[11px] text-pulse"><span className="pulse-dot" /> live</span>}>
            What the agent is doing
          </SectionTitle>
          <Card className="p-0">
            {events.length === 0 ? (
              <div className="p-5"><Empty>No activity yet — the agent will start as soon as a scan completes.</Empty></div>
            ) : (
              <ul className="divide-y divide-border">
                {events.slice(0, 10).map((e, i) => (
                  <li key={i} className="flex items-center gap-3 px-5 py-3">
                    <EventIcon kind={e.kind} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm">{e.title}</div>
                      {e.meta && <div className="mono truncate text-xs text-faint">{e.meta}</div>}
                    </div>
                    <span className="shrink-0 text-xs text-faint">{timeAgo(e.at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        {/* Compliance posture */}
        <div>
          <SectionTitle action={<Link href="/compliance" className="text-[11px] font-medium text-accent hover:underline">all →</Link>}>
            Compliance
          </SectionTitle>
          <Card className="space-y-2 p-3">
            {frameworks.length === 0 ? (
              <div className="p-2"><Empty>No control state yet.</Empty></div>
            ) : (
              frameworks.map(({ framework, gap }) => (
                <Link key={framework} href={`/compliance/${framework}`} className="flex items-center justify-between rounded-xl border border-border bg-surface-2 px-3 py-2.5 text-sm transition hover:border-border-strong">
                  <span className="font-medium">{FRAMEWORK_LABEL[framework] ?? framework}</span>
                  <span className="inline-flex items-center gap-2 text-xs">
                    {gap === 0 ? (
                      <span className="inline-flex items-center gap-1 text-pulse"><CheckCircle2 className="h-3.5 w-3.5" /> on track</span>
                    ) : (
                      <span className="text-high">{gap} gap{gap > 1 ? "s" : ""}</span>
                    )}
                  </span>
                </Link>
              ))
            )}
          </Card>
        </div>
      </div>

      {/* Noise reduction — the unified-platform value made concrete: duplicate
          findings across scanners collapsed into single issues. Shown when it helped. */}
      {merged > 0 && (
        <Link href="/issues" className="group flex items-center gap-3 rounded-xl border border-border bg-surface px-5 py-3.5 transition hover:border-border-strong">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-pulse-soft text-pulse">
            <Layers className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1 text-sm">
            <span className="font-semibold">{issuesResp.raw_findings} findings unified into {issuesResp.count} issues</span>
            <span className="text-muted"> — {noisePct}% less duplicate noise to triage.</span>
          </div>
          <ArrowRight className="h-4 w-4 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
        </Link>
      )}

      {/* Cross-surface attack paths — the unified cross-detection signal: a single
          weakness chaining across surfaces to a crown jewel. Only shown when present. */}
      {attackPaths.count > 0 && (
        <Link
          href="/attack-paths"
          className="group flex items-center gap-3 rounded-xl border border-high/40 bg-high/5 px-5 py-4 transition hover:border-high/60"
        >
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-high/10 text-high">
            <Spline className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold">
              {attackPaths.count} cross-surface attack path{attackPaths.count === 1 ? "" : "s"}
            </div>
            <p className="text-xs text-muted">
              A weakness on one surface chains, through a shared identifier, to a crown jewel on another.
            </p>
          </div>
          <ArrowRight className="h-4 w-4 shrink-0 text-high transition group-hover:translate-x-0.5" />
        </Link>
      )}

      {/* Risk by category — where the risk lives, at a glance */}
      {byCategory.length > 0 && (
        <div>
          <SectionTitle action={<Link href="/findings" className="text-[11px] font-medium text-accent hover:underline">all findings →</Link>}>
            <span className="inline-flex items-center gap-1.5"><Boxes className="h-3.5 w-3.5 text-faint" /> Risk by category</span>
          </SectionTitle>
          <Card className="p-0">
            <ul className="divide-y divide-border">
              {byCategory.map((c) => (
                <li key={c.category}>
                  <Link href="/findings" className="flex items-center gap-3 px-5 py-3 transition hover:bg-surface-2">
                    <span className="min-w-0 flex-1 truncate text-sm font-medium">{c.category}</span>
                    <span className="flex items-center gap-2.5 text-xs">
                      {c.critical > 0 && <span className="font-semibold text-critical">{c.critical} critical</span>}
                      {c.high > 0 && <span className="font-semibold text-high">{c.high} high</span>}
                      {c.medium > 0 && <span className="text-medium">{c.medium} med</span>}
                      {c.low > 0 && <span className="text-faint">{c.low} low</span>}
                      <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-faint">{c.total}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      {/* Top findings — for the security-minded, de-emphasized */}
      {findings.length > 0 && (
        <div>
          <SectionTitle action={<Link href="/findings" className="text-[11px] font-medium text-accent hover:underline">all findings →</Link>}>
            <span className="inline-flex items-center gap-1.5"><Radar className="h-3.5 w-3.5 text-faint" /> Top findings · for your security team</span>
          </SectionTitle>
          <Card className="p-0">
            <ul className="divide-y divide-border">
              {[...findings]
                .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
                .slice(0, 6)
                .map((f) => (
                  <li key={f.id}>
                    <Link href={`/findings/${f.id}`} className="flex items-center gap-3 px-5 py-3 transition hover:bg-surface-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="min-w-0 flex-1 truncate text-sm">{f.title}</span>
                      <span className="mono shrink-0 text-xs text-faint">{f.tool}</span>
                    </Link>
                  </li>
                ))}
            </ul>
          </Card>
        </div>
      )}
    </div>
  );
}

function HandledStat({ icon: Icon, n, label, tone }: { icon: typeof Plug; n: number; label: string; tone?: string }) {
  return (
    <Card className="flex items-center gap-3 p-4">
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface-2 text-muted">
        <Icon className="h-4 w-4" />
      </span>
      <div className="min-w-0">
        <div className={`text-xl font-semibold leading-none ${tone ?? "text-ink"}`}>{n}</div>
        <div className="mt-1 truncate text-xs text-muted">{label}</div>
      </div>
    </Card>
  );
}

function EventIcon({ kind }: { kind: Event["kind"] }) {
  const map = {
    detected: { Icon: ShieldAlert, cls: "text-high bg-high/10" },
    resolved: { Icon: Wrench, cls: "text-pulse bg-pulse-soft" },
    scanned: { Icon: ScanLine, cls: "text-accent bg-accent-soft" },
  } as const;
  const { Icon, cls } = map[kind];
  return (
    <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${cls}`}>
      <Icon className="h-3.5 w-3.5" />
    </span>
  );
}
