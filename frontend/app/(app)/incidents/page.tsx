import Link from "next/link";
import { ShieldAlert, CheckCircle2, Wrench, ArrowRight, Flame, TimerOff, CalendarClock } from "lucide-react";
import { api } from "@/lib/api";
import type { Incident } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { AckButton } from "@/components/incidents/ack-button";
import { SOCScorecard } from "@/components/incidents/soc-scorecard";
import { timeAgo, duration } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  // Join incidents to the gated actions so an OPEN incident can show the agent's response
  // (the detect→respond half) — a queued fix awaiting approval, not just the detection.
  const [all, approvals, windows, soc] = await Promise.all([api.incidents("all"), api.approvals(), api.maintenanceWindows(), api.socMetrics()]);
  const now = Date.now();
  const activeWindow = windows.find((w) => new Date(w.starts_at).getTime() <= now && now < new Date(w.ends_at).getTime());
  const pending = new Set(approvals.map((a) => a.finding_id).filter(Boolean));
  const open = all.filter((i) => i.status === "open").sort(byTime("opened_at"));
  const resolved = all.filter((i) => i.status === "resolved").sort(byTime("resolved_at"));
  const mttr = meanResolveMs(resolved);
  const slaBreached = open.filter((i) => i.sla_breach && (i.sla_breach.ack_breached || i.sla_breach.resolve_breached)).length;

  return (
    <div className="space-y-6">
      <PageIntro
        icon={ShieldAlert}
        title="Incidents"
        description="What changed since the last scan. The agent watches your stack around the clock, opens an incident the moment a serious new issue appears, and tracks it until it's fixed — so nothing slips through unnoticed."
        right={
          <div className="flex gap-4 text-sm">
            <Stat n={open.length} label="open" tone="text-high" />
            {slaBreached > 0 && <Stat n={slaBreached} label="SLA breached" tone="text-critical" />}
            <Stat n={resolved.length} label="resolved" tone="text-pulse" />
            {mttr !== null && <Stat n={fmtMs(mttr)} label="avg time to resolve" tone="text-ink" />}
          </div>
        }
      />

      <SOCScorecard m={soc} />

      {activeWindow && (
        <div className="flex items-center gap-2.5 rounded-lg border border-medium/30 bg-medium/10 px-3.5 py-2.5 text-sm text-ink">
          <CalendarClock className="h-4 w-4 shrink-0 text-medium" />
          <span>
            <span className="font-medium">Maintenance window active</span> — alerting is paused (no new incidents open, no
            escalation) until {new Date(activeWindow.ends_at).toLocaleString()}. <span className="text-muted">{activeWindow.name}</span>
          </span>
        </div>
      )}

      <section>
        <SubHead>Open · needs attention</SubHead>
        {open.length === 0 ? (
          <Empty>No open incidents — nothing has broken since the last pass.</Empty>
        ) : (
          <Timeline>
            {open.map((i) => (
              <Node key={i.id} incident={i} resolved={false} respondPending={!!i.finding_id && pending.has(i.finding_id)} />
            ))}
          </Timeline>
        )}
      </section>

      <section>
        <SubHead>Resolved · the agent&apos;s wins</SubHead>
        {resolved.length === 0 ? (
          <Empty>No resolved incidents yet.</Empty>
        ) : (
          <Timeline>
            {resolved.slice(0, 25).map((i) => (
              <Node key={i.id} incident={i} resolved respondPending={false} />
            ))}
          </Timeline>
        )}
      </section>
    </div>
  );
}

function byTime(field: "opened_at" | "resolved_at") {
  return (a: Incident, b: Incident) => new Date(b[field] ?? 0).getTime() - new Date(a[field] ?? 0).getTime();
}

// meanResolveMs averages (resolved_at − opened_at) over resolved incidents with both
// timestamps — the agent's mean-time-to-resolve. null when there's nothing to average.
function meanResolveMs(resolved: Incident[]): number | null {
  const spans = resolved
    .map((i) => (i.opened_at && i.resolved_at ? new Date(i.resolved_at).getTime() - new Date(i.opened_at).getTime() : NaN))
    .filter((ms) => Number.isFinite(ms) && ms >= 0);
  if (spans.length === 0) return null;
  return spans.reduce((a, b) => a + b, 0) / spans.length;
}

function fmtMs(ms: number): string {
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

function SubHead({ children }: { children: React.ReactNode }) {
  return <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-muted">{children}</h2>;
}

function Stat({ n, label, tone }: { n: number | string; label: string; tone: string }) {
  return (
    <div className="text-right">
      <span className={`text-xl font-semibold ${tone}`}>{n}</span> <span className="text-xs text-faint">{label}</span>
    </div>
  );
}

function Timeline({ children }: { children: React.ReactNode }) {
  return <ol className="relative space-y-2 border-l border-border pl-5">{children}</ol>;
}

function Node({ incident: i, resolved, respondPending }: { incident: Incident; resolved: boolean; respondPending: boolean }) {
  const Icon = resolved ? CheckCircle2 : ShieldAlert;
  // The incident links to the finding that opened it — incident → evidence.
  const href = i.finding_id ? `/findings/${i.finding_id}` : undefined;
  const body = (
    <div className="card flex items-center gap-3 px-4 py-3 transition hover:border-border-strong">
      <Icon className={`h-4 w-4 shrink-0 ${resolved ? "text-pulse" : "text-high"}`} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={i.severity} className="scale-90" />
          <span className="truncate text-sm">{i.title}</span>
          {i.attacked && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[10px] font-semibold text-critical">
              <Flame className="h-2.5 w-2.5" /> under attack
            </span>
          )}
          <ConfidenceBadge verification={i.verification} confidence={i.confidence} />
          {respondPending && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-accent-soft px-2 py-0.5 text-[10px] font-medium text-accent ring-1 ring-accent/30">
              <Wrench className="h-2.5 w-2.5" /> fix ready
            </span>
          )}
          {!resolved && <AckButton id={i.id} acknowledged={!!i.acknowledged_at} by={i.acknowledged_by} />}
          {!resolved && i.sla_breach && (i.sla_breach.ack_breached || i.sla_breach.resolve_breached) && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[10px] font-semibold text-critical">
              <TimerOff className="h-2.5 w-2.5" /> SLA {i.sla_breach.resolve_breached ? "resolve" : "ack"} breached
            </span>
          )}
        </div>
        <div className="mono mt-0.5 truncate text-[11px] text-faint">{i.rule_id}</div>
      </div>
      <div className="shrink-0 text-right text-xs">
        {resolved ? (
          <>
            <div className="text-pulse">fixed {timeAgo(i.resolved_at)}</div>
            <div className="text-faint">open for {duration(i.opened_at, i.resolved_at)}</div>
          </>
        ) : (
          <div className="text-muted">detected {timeAgo(i.opened_at)}</div>
        )}
      </div>
      {href && <ArrowRight className="h-4 w-4 shrink-0 text-faint" />}
    </div>
  );
  return (
    <li className="animate-fade-rise">
      <span
        className={`absolute -left-[9px] grid h-4 w-4 place-items-center rounded-full border-2 border-bg ${
          resolved ? "bg-pulse" : "bg-high"
        }`}
      />
      {href ? <Link href={href} className="block">{body}</Link> : body}
    </li>
  );
}

// ConfidenceBadge is the FP-control signal on an alert: a verified/corroborated incident is shown as
// confirmed, while an unconfirmed pattern_match is flagged "confirm" — so we never present a low-confidence
// finding as a confident incident ("no high false positive"). No badge when the engine gave no signal.
function ConfidenceBadge({ verification, confidence }: { verification?: string; confidence?: number }) {
  if (!verification) return null;
  const pct = confidence ? ` ${Math.round(confidence * 100)}%` : "";
  if (verification === "verified")
    return <span className="inline-flex shrink-0 items-center rounded-full bg-pulse/10 px-2 py-0.5 text-[10px] font-semibold text-pulse" title={`Exploit-verified${pct ? ` · confidence${pct}` : ""}`}>verified{pct}</span>;
  if (verification === "corroborated")
    return <span className="inline-flex shrink-0 items-center rounded-full bg-accent-soft px-2 py-0.5 text-[10px] font-medium text-accent ring-1 ring-accent/30" title={`Corroborated by ≥2 independent tools${pct ? ` · confidence${pct}` : ""}`}>corroborated{pct}</span>;
  // pattern_match (or anything unconfirmed) → tell the user it needs confirming, don't dress it as confirmed
  return <span className="inline-flex shrink-0 items-center rounded-full border border-medium/40 bg-medium/10 px-2 py-0.5 text-[10px] font-medium text-medium" title={`Single-tool pattern match — confirm before acting${pct ? ` · confidence${pct}` : ""}`}>confirm{pct}</span>;
}
