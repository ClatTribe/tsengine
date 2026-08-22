import Link from "next/link";
import { ShieldAlert, CheckCircle2, Wrench, ArrowRight, Flame, TimerOff, CalendarClock, Skull } from "lucide-react";
import { api } from "@/lib/api";
import type { Incident, SLABreach } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { AckButton } from "@/components/incidents/ack-button";
import { SOCScorecard } from "@/components/incidents/soc-scorecard";
import { timeAgo, duration } from "@/lib/utils";

export const dynamic = "force-dynamic";

// slaReason says why a deadline is short. Each flag's Go doc states that it exists for this — "so
// the UI can say WHY the clock is short instead of showing an unexplained deadline", and "rather
// than leaving a reader to assume we are being dramatic" — and none were rendered, so the badge
// read "SLA resolve breached" with no reason at all.
//
// Ordered strongest-first and only one is shown: a responder needs the reason, not the derivation.
function slaReason(b: SLABreach): string | null {
  if (b.ransomware_accelerated) return "ransomware clock";
  if (b.cisa_deadline) return "CISA's published date";
  if (b.kev_accelerated) return "exploited in the wild";
  return null;
}

// cisaDue reads the incident's CISA BOD 22-01 deadline. Returns null when there is none — most
// incidents have no KEV CVE behind them, and a badge on every row is a badge nobody reads.
//
// Overdue is computed against the ABSOLUTE date CISA published, never against when we opened the
// incident: a CVE catalogued months ago is already past its deadline the moment it is detected, and
// the whole reason the date is carried verbatim is to avoid restarting a clock the authority has
// already run out.
function cisaDue(i: Incident): { label: string; overdue: boolean } | null {
  if (!i.kev_due_at) return null;
  const due = new Date(i.kev_due_at);
  if (Number.isNaN(due.getTime())) return null;
  return {
    label: due.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }),
    overdue: due.getTime() < Date.now(),
  };
}

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

      {open.length > 0 && (
        <p className="text-xs leading-relaxed text-muted">
          Badge guide: <span className="font-medium text-pulse">verified</span> = reproduced with a safe
          proof-of-concept · <span className="font-medium text-accent">corroborated</span> = two or more
          independent tools agree · <span className="font-medium text-medium">confirm</span> = a single-tool
          match to sanity-check before acting · <span className="font-medium text-critical">reaches …</span> = it
          chains to a crown jewel, so the impact is bigger than its own severity.
        </p>
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
          <TriageBadge verdict={i.triage_verdict} skill={i.triage_skill} />
          <BlastRadiusBadge blast={i.blast_radius} />
          <ConfirmingFixBadge status={i.status} absentPasses={i.absent_passes} />
          {respondPending && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-accent-soft px-2 py-0.5 text-[10px] font-medium text-accent ring-1 ring-accent/30">
              <Wrench className="h-2.5 w-2.5" /> fix ready
            </span>
          )}
          {!resolved && <AckButton id={i.id} acknowledged={!!i.acknowledged_at} by={i.acknowledged_by} />}
          {/* Ransomware use is a strictly stronger claim than KEV listing — exploited in the wild
              versus exploited by crews who encrypt the estate. It outranks severity for ordering
              work, and the queue showed neither it nor the deadline below. */}
          {/* The base exploitation fact. The deadline badge below follows FROM this, and the queue
              could show the deadline without being able to state the reason for it. */}
          {i.kev && !i.ransomware && (
            <span
              className="inline-flex shrink-0 items-center gap-1 rounded-full bg-high/10 px-2 py-0.5 text-[10px] font-semibold text-high"
              title="On CISA's Known Exploited Vulnerabilities catalogue — observed exploited in the wild"
            >
              <Flame className="h-2.5 w-2.5" /> known exploited
            </span>
          )}
          {i.ransomware && (
            <span
              className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[10px] font-semibold text-critical"
              title="CISA records this CVE as used in known ransomware campaigns — a stronger claim than being exploited in the wild"
            >
              <Skull className="h-2.5 w-2.5" /> ransomware
            </span>
          )}
          {!resolved && cisaDue(i) && (
            // CISA's OWN due date, verbatim. Past-due is the common case rather than the exception:
            // a CVE catalogued months ago arrives already overdue, and a window computed from when we
            // opened the incident would have quietly restarted a clock the authority already ran out.
            <span
              className={
                "inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold " +
                (cisaDue(i)!.overdue ? "bg-critical/10 text-critical" : "bg-surface-2 text-muted ring-1 ring-border")
              }
              title="CISA BOD 22-01 remediation deadline for this CVE — published by CISA, not computed by us"
            >
              <CalendarClock className="h-2.5 w-2.5" />
              {cisaDue(i)!.overdue ? `CISA deadline passed ${cisaDue(i)!.label}` : `CISA due ${cisaDue(i)!.label}`}
            </span>
          )}
          {!resolved && i.sla_breach && (i.sla_breach.ack_breached || i.sla_breach.resolve_breached) && (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[10px] font-semibold text-critical">
              <TimerOff className="h-2.5 w-2.5" /> SLA {i.sla_breach.resolve_breached ? "resolve" : "ack"} breached
              {slaReason(i.sla_breach) && <span className="font-normal"> · {slaReason(i.sla_breach)}</span>}
            </span>
          )}
        </div>
        <div className="mono mt-0.5 truncate text-[11px] text-faint">{i.rule_id}</div>
        {/* The skill's reasoning — the point of Detection Skills is that the analyst inherits the
            detection engineer's thinking instead of rediscovering it, so it belongs on the row
            itself, not behind a click. */}
        {i.triage_rationale && (
          <div className="mt-1 truncate text-[11px] text-muted" title={i.triage_rationale}>
            <span className="text-faint">triage:</span> {i.triage_rationale}
          </div>
        )}
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

// ConfirmingFixBadge says an open incident's issue has stopped appearing but is being held open until
// the absence repeats. Without it the queue renders "still firing" and "gone from the last scan" the
// same way — and the person most likely to be looking is the one who just deployed the fix, for whom
// an unchanged alert reads as the fix having failed. Only the count we actually have is stated; the
// configured threshold is a server-side policy this page is not told, and naming a number we cannot
// see would be inventing the very thing the badge exists to be honest about.
function ConfirmingFixBadge({ status, absentPasses }: { status?: string; absentPasses?: number }) {
  const n = typeof absentPasses === "number" ? absentPasses : 0;
  if (status !== "open" || n < 1) return null;
  return (
    <span
      className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted"
      title="This issue did not appear in the most recent scan(s), but one quiet scan is not proof it is gone — a scanner can succeed and simply report less. The incident stays open until the absence repeats, then resolves."
    >
      confirming fix · absent {n} {n === 1 ? "scan" : "scans"}
    </span>
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

// BlastRadiusBadge sizes the impact: an incident that chains to a crown jewel (e.g. cloud root) is far worse
// than its own severity implies. Only shown when the engine actually found such a chain (grounded) — so a
// contained issue never gets an inflated impact tag.
// TriageBadge shows a Detection Skill's verdict (ADR 0017). The tooltip names the exact skill
// version, so an analyst can see whose reasoning this is — and a wrong verdict is traceable to a
// specific skill rather than to "the AI".
//
// A "benign" verdict is shown MUTED, never as a dismissal: the incident is open because a real
// finding crossed the severity floor, and a third-party skill's opinion does not overrule that. The
// verdict is context for the human, not a decision.
function TriageBadge({ verdict, skill }: { verdict?: string; skill?: string }) {
  if (!verdict) return null;
  const tone: Record<string, string> = {
    malicious: "bg-critical/10 text-critical",
    suspicious: "bg-high/10 text-high",
    inconclusive: "bg-surface text-muted ring-1 ring-border",
    benign: "bg-surface text-faint ring-1 ring-border",
  };
  const title = skill ? `Detection Skill verdict — ${skill}` : "Detection Skill verdict";
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[10px] font-semibold ${tone[verdict] ?? tone.inconclusive}`}
      title={title}
    >
      {verdict}
    </span>
  );
}

function BlastRadiusBadge({ blast }: { blast?: { reaches_crown_jewel: boolean; crown_jewel_type?: string; hops?: number } }) {
  if (!blast?.reaches_crown_jewel) return null;
  const jewel = (blast.crown_jewel_type ?? "a crown jewel").replace(/_/g, " ");
  const reach = blast.hops && blast.hops > 0 ? `${blast.hops}-hop path to ${jewel}` : `on ${jewel}`;
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[10px] font-semibold text-critical" title={`Blast radius: this chains to ${jewel} — impact is bigger than its severity (${reach})`}>
      reaches {jewel}
    </span>
  );
}
