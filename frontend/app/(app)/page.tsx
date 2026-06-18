import Link from "next/link";
import { ArrowRight, ScanLine, ShieldAlert, ShieldCheck, Wrench, Inbox as InboxIcon } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL } from "@/lib/api";
import { riskRating, severityCounts, sevRank, timeAgo } from "@/lib/utils";
import { Card, SectionTitle, SeverityBadge, Empty } from "@/components/ui/primitives";
import { FirstRun } from "@/components/onboarding/first-run";

const RISK_COPY: Record<string, string> = {
  Critical: "Critical issues are open. The agent has queued fixes for your approval.",
  High: "High-severity issues need attention. Review the agent's proposals.",
  Medium: "A few medium issues remain. Nothing urgent.",
  Low: "Only low-severity items left. You're in good shape.",
  Clear: "No open issues. The agent is watching continuously.",
};
const RISK_TONE: Record<string, string> = {
  Critical: "text-critical",
  High: "text-high",
  Medium: "text-medium",
  Low: "text-low",
  Clear: "text-pulse",
};

type Event = { at: string; kind: "detected" | "resolved" | "scanned"; title: string; meta?: string };

export default async function OverviewPage() {
  // Cold start: with nothing connected the dashboard is empty and meaningless — lead the
  // user straight into onboarding instead.
  const connections = await api.connections();
  if (connections.length === 0) return <FirstRun />;

  const [findings, incidents, approvals, engagements] = await Promise.all([
    api.findings(),
    api.incidents("all"),
    api.approvals(),
    api.engagements(),
  ]);

  const counts = severityCounts(findings);
  const risk = riskRating(counts);

  // Synthesize the agent activity feed from what the agent actually did.
  const events: Event[] = [];
  for (const i of incidents) {
    if (i.status === "resolved" && i.resolved_at)
      events.push({ at: i.resolved_at, kind: "resolved", title: i.title, meta: i.rule_id });
    else events.push({ at: i.opened_at, kind: "detected", title: i.title, meta: i.rule_id });
  }
  for (const e of engagements)
    if (e.completed_at) events.push({ at: e.completed_at, kind: "scanned", title: `Scanned an asset`, meta: e.trigger });
  events.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());

  const posture = await Promise.all(
    FRAMEWORKS.map(async (f) => {
      const cs = await api.posture(f);
      if (cs.length === 0) return null;
      const gap = cs.filter((c) => c.state === "gap").length;
      return { f, met: cs.length - gap, gap };
    }),
  );
  const frameworks = posture.filter(Boolean) as { f: string; met: number; gap: number }[];

  return (
    <div className="space-y-6">
      {/* Risk hero */}
      <Card className="flex flex-col gap-5 md:flex-row md:items-center">
        <div className="flex items-center gap-4">
          <div className={`grid h-14 w-14 place-items-center rounded-2xl border border-border bg-surface-2 ${RISK_TONE[risk]}`}>
            {risk === "Clear" ? <ShieldCheck className="h-7 w-7" /> : <ShieldAlert className="h-7 w-7" />}
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-muted">Posture</div>
            <div className={`text-3xl font-semibold leading-tight ${RISK_TONE[risk]}`}>{risk}</div>
          </div>
        </div>
        <p className="max-w-md text-sm text-muted">{RISK_COPY[risk]}</p>
        <div className="ml-auto grid grid-cols-4 gap-2">
          {(["critical", "high", "medium", "low"] as const).map((s) => (
            <div key={s} className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-center">
              <div className={`text-xl font-semibold ${RISK_TONE[s === "critical" ? "Critical" : s === "high" ? "High" : s === "medium" ? "Medium" : "Low"]}`}>
                {counts[s]}
              </div>
              <div className="text-[10px] uppercase tracking-wide text-faint">{s}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Needs you */}
      {approvals.length > 0 && (
        <Link href="/inbox" className="block">
          <Card className="flex items-center gap-4 border-accent/30 transition hover:border-accent/60">
            <div className="grid h-10 w-10 place-items-center rounded-lg bg-accent-soft text-accent">
              <InboxIcon className="h-5 w-5" />
            </div>
            <div>
              <div className="text-sm font-medium">
                {approvals.length} fix{approvals.length > 1 ? "es" : ""} awaiting your approval
              </div>
              <div className="text-xs text-muted">The agent prepared these and is holding for your decision.</div>
            </div>
            <ArrowRight className="ml-auto h-4 w-4 text-accent" />
          </Card>
        </Link>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Activity feed (2 cols) */}
        <div className="lg:col-span-2">
          <SectionTitle action={<span className="text-[11px] text-faint">live</span>}>Agent activity</SectionTitle>
          <Card className="p-0">
            {events.length === 0 ? (
              <div className="p-5">
                <Empty>No activity yet — connect a system to put the agent to work.</Empty>
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {events.slice(0, 12).map((e, i) => (
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
          <SectionTitle action={<Link href="/compliance" className="text-[11px] text-accent hover:underline">all →</Link>}>
            Compliance
          </SectionTitle>
          <Card className="space-y-2.5">
            {frameworks.length === 0 ? (
              <Empty>No control state yet.</Empty>
            ) : (
              frameworks.map(({ f, met, gap }) => (
                <Link key={f} href={`/compliance/${f}`} className="flex items-center justify-between rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm transition hover:border-border-strong">
                  <span>{FRAMEWORK_LABEL[f] ?? f}</span>
                  <span className="text-xs">
                    <span className="text-low">{met} met</span>
                    <span className="text-faint"> · </span>
                    <span className="text-high">{gap} gap</span>
                  </span>
                </Link>
              ))
            )}
          </Card>
        </div>
      </div>

      {/* Top findings preview */}
      <div>
        <SectionTitle action={<Link href="/findings" className="text-[11px] text-accent hover:underline">all →</Link>}>Top findings</SectionTitle>
        <Card className="p-0">
          {findings.length === 0 ? (
            <div className="p-5">
              <Empty>No open findings.</Empty>
            </div>
          ) : (
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
          )}
        </Card>
      </div>
    </div>
  );
}

function EventIcon({ kind }: { kind: Event["kind"] }) {
  const map = {
    detected: { Icon: ShieldAlert, cls: "text-high bg-high/10" },
    resolved: { Icon: Wrench, cls: "text-pulse bg-pulse/10" },
    scanned: { Icon: ScanLine, cls: "text-accent bg-accent-soft" },
  } as const;
  const { Icon, cls } = map[kind];
  return (
    <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${cls}`}>
      <Icon className="h-3.5 w-3.5" />
    </span>
  );
}
