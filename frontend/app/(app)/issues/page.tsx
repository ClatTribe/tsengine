import Link from "next/link";
import { ShieldCheck, ArrowRight, Flame, Layers, Zap, Crosshair, Bug, Globe, Spline, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import type { Issue } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { IssueActions } from "@/components/issues/issue-actions";
import { IssueAutofix } from "@/components/issues/issue-autofix";
import { IssueInvestigate } from "@/components/issues/issue-investigate";
import { ExclusionRules } from "@/components/issues/exclusion-rules";
import { TriageFunnel } from "@/components/issues/triage-funnel";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function IssuesPage({ searchParams }: { searchParams: Promise<{ show?: string }> }) {
  const show = (await searchParams).show;
  const showingIgnored = show === "ignored";
  const showingLive = show === "live";
  const showingExternal = show === "external";
  const [{ issues, count, raw_findings, confirmed, ignored, excluded, attacked, live }, exclResp, funnel, llm] = await Promise.all([
    api.issues(showingIgnored),
    api.exclusions(),
    api.triageFunnel(),
    api.llmSettings(),
  ]);
  const aiEnabled = llm.ai_enabled;
  // View filters over the SAME unified list (no separate pages): "Live" = the genuinely-live subset,
  // "External" = internet/attacker-eye exposure (the old OSINT page — those findings carry tool "osint"
  // and already flow into Issues, so here they're just a source filter, not a destination).
  const isExternal = (i: (typeof issues)[number]) => i.tools?.includes("osint");
  const externalCount = issues.filter(isExternal).length;
  const visible = showingExternal ? issues.filter(isExternal) : showingLive ? issues.filter((i) => i.live) : issues;
  const mainView = !showingIgnored && !showingLive && !showingExternal;
  const collapsed = Math.max(0, raw_findings - count);

  return (
    <div className="space-y-6">
      <PageIntro
        icon={Layers}
        title="Issues"
        description="Everything that needs fixing, in one list. We pull together every weakness across your code, cloud, apps, identity, and what's exposed on the internet — merge the duplicates, rank by real risk, and flag what's new or under active attack — so you work one prioritized list instead of juggling separate reports. The raw per-tool detail is one tab away."
        right={
          <div className="flex gap-4 text-sm">
            <Stat n={showingLive || showingExternal ? visible.length : count} label={showingIgnored ? "ignored" : showingLive ? "live" : showingExternal ? "external" : "issues"} tone="text-ink" />
            {mainView && (live ?? 0) > 0 && <Stat n={live ?? 0} label="live · exploitable" tone="text-critical" />}
            {mainView && (attacked ?? 0) > 0 && <Stat n={attacked ?? 0} label="under attack" tone="text-critical" />}
            {mainView && <Stat n={confirmed} label="multi-tool confirmed" tone="text-pulse" />}
            {mainView && collapsed > 0 && <Stat n={collapsed} label="duplicates merged" tone="text-faint" />}
          </div>
        }
      />

      <PageTabs tabs={[{ href: "/issues", label: "Issues" }, { href: "/findings", label: "All findings" }]} />

      {/* AI Security Engineer state — honest: this list is deterministically ranked (severity × data-tier ×
          attack-path). The AI doesn't silently re-rank it; it's an ACTION you run. So we show whether it's
          ON and point to the console, or prompt to turn it on — never claim "AI ranked this". */}
      {mainView && (
        <Link
          href="/brief"
          className={`group flex items-center gap-2.5 rounded-xl border px-4 py-2.5 text-sm transition ${
            aiEnabled
              ? "border-accent/30 bg-accent-soft/30 hover:border-accent/60"
              : "border-border bg-surface hover:border-accent/40"
          }`}
        >
          <Sparkles className={`h-4 w-4 shrink-0 ${aiEnabled ? "text-accent" : "text-muted"}`} />
          <span className="min-w-0 flex-1 text-muted">
            {aiEnabled ? (
              <>
                <span className="font-medium text-ink">Your AI Security Engineer is on.</span> Have it dig deeper,
                re-rank by real impact, and explain each issue in plain English.
              </>
            ) : (
              <>
                <span className="font-medium text-ink">Turn on your AI Security Engineer</span> to triage this list,
                rank by real impact, and explain every issue — beyond the deterministic scan.
              </>
            )}
          </span>
          <span className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-accent">
            {aiEnabled ? "Triage & prioritize" : "Enable"} <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
          </span>
        </Link>
      )}

      {/* View filters over the one list — no separate pages. Live = exploitable subset; External = the
          internet/attacker-eye (old OSINT) slice; raw per-tool detail is the "All findings" tab above. */}
      <div className="flex items-center rounded-lg border border-border bg-surface p-0.5 text-sm w-fit">
        <Tab href="/issues" active={mainView}>Active</Tab>
        <Tab href="/issues?show=live" active={showingLive}>
          <span className="inline-flex items-center gap-1"><Zap className="h-3 w-3" /> Live{(live ?? 0) > 0 ? ` (${live})` : ""}</span>
        </Tab>
        {externalCount > 0 && (
          <Tab href="/issues?show=external" active={showingExternal}>
            <span className="inline-flex items-center gap-1"><Globe className="h-3 w-3" /> External ({externalCount})</span>
          </Tab>
        )}
        <Tab href="/issues?show=ignored" active={showingIgnored}>
          Ignored{typeof ignored === "number" && ignored > 0 ? ` (${ignored})` : ""}
        </Tab>
      </div>

      {showingLive && (
        <p className="text-sm text-muted">
          The few issues that are genuinely <span className="font-medium text-ink">live</span> — observed under attack, or
          internet-exposed on a real path to something that matters — not just present in a posture scan.
        </p>
      )}

      {showingExternal && (
        <p className="text-sm text-muted">
          Your <span className="font-medium text-ink">internet / attacker-eye exposure</span> — leaked credentials, exposed
          hosts, typosquats, certificate issues — discovered from open sources. These already sit in your main list; this is
          just that slice.
        </p>
      )}

      {/* Plain-English legend for the header stats — the ICP is a non-security founder, so the
          trust signals in the stat row shouldn't be jargon. */}
      {mainView && (
        <p className="text-xs leading-relaxed text-muted">
          <span className="font-medium text-pulse">Multi-tool confirmed</span> = at least two independent scanners
          flagged it (the strongest signal it&apos;s real, not a false alarm). <span className="font-medium text-critical">Live · exploitable</span> = we have
          evidence it&apos;s reachable and abusable right now. <span className="font-medium text-critical">Under attack</span> = seen being exploited in your live traffic.
        </p>
      )}

      {/* Auto-triage funnel — the quantified noise reduction (% the engine handled for you) */}
      {mainView && <TriageFunnel f={funnel} />}

      {/* Custom exclusion rules (path/package/rule noise filters) */}
      {mainView && <ExclusionRules rules={exclResp.exclusions} excluded={excluded ?? 0} />}

      {/* "Start here" — the AI Security Engineer's outcome #1 (figure out what to work on). The list is
          already risk-ranked (severity × data-tier × attack-path), so the top row IS the #1 fix; we just
          make it prominent with its impact reason + the agentic verbs, so a founder isn't parsing a table. */}
      {mainView && visible.length > 0 && <LeadCard issue={visible[0]} />}

      {visible.length === 0 ? (
        <Empty>
          {showingIgnored
            ? "No ignored issues. Suppressed issues (false-positive / accepted-risk) appear here and can be restored."
            : showingLive
              ? "Nothing live right now — no issue is under active attack or internet-exposed on an attack path. The full list is under Active."
              : showingExternal
                ? "No internet-facing exposure found — no leaked credentials, exposed hosts, or look-alike domains. The full list is under Active."
                : "No open issues. As scanners run across your code, cloud, and surfaces, their findings are de-duplicated here into one row per real problem."}
        </Empty>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full min-w-[560px]">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                <th className="py-2.5 pl-5 pr-2 font-medium">Severity</th>
                <th className="px-2 py-2.5 font-medium">Issue</th>
                <th className="px-2 py-2.5 font-medium">Detected by</th>
                <th className="py-2.5 pr-5 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((it) => (
                <IssueRow key={it.key} issue={it} ignored={showingIgnored} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Tab({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      className={cn("rounded-md px-3 py-1 text-xs transition", active ? "bg-accent-soft text-accent" : "text-muted hover:text-ink")}
    >
      {children}
    </Link>
  );
}

// LeadCard — "Start here": the single highest-priority issue (the list is already risk-ranked), made
// prominent with its plain-English impact reason + the two agentic verbs (Investigate, AI Fix). This is
// outcome #1 of the AI Security Engineer — "figure out the issue to work on" — without making a founder
// parse a table. Deterministic + grounded (the reason comes from real signals on the issue).
function LeadCard({ issue }: { issue: Issue }) {
  const reason =
    issue.live_reason ||
    (issue.attacked ? "Seen under attack in your live traffic — fix this now." : "") ||
    (issue.kev ? "On CISA KEV — actively exploited in the wild (BOD 22-01: patch now)." : "") ||
    (issue.in_attack_path ? "On an attack path to something that matters — that's why it leads." : "") ||
    (issue.confirmed ? "Confirmed by multiple independent scanners — not a false alarm." : "") ||
    "Your highest risk-ranked issue across every surface.";
  return (
    <div className="rounded-2xl border border-accent/30 bg-accent-soft/20 p-5">
      <div className="mb-2.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-accent">
        <Sparkles className="h-3.5 w-3.5" /> Start here — your #1 fix
      </div>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={issue.severity} />
            <span className="truncate text-sm font-medium text-ink">{issue.title}</span>
          </div>
          <p className="mt-1.5 text-sm leading-relaxed text-muted">{reason}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <IssueInvestigate issueKey={issue.key} title={issue.title} />
          {issue.finding_ids[0] && <IssueAutofix findingId={issue.finding_ids[0]} title={issue.title} />}
        </div>
      </div>
    </div>
  );
}

function IssueRow({ issue, ignored }: { issue: Issue; ignored: boolean }) {
  // The issue links to one of its underlying findings (the evidence).
  const href = issue.finding_ids[0] ? `/findings/${issue.finding_ids[0]}` : undefined;
  const title = <span className="truncate text-sm">{issue.title}</span>;
  return (
    <tr className="group border-b border-border last:border-0 transition hover:bg-surface-2">
      <td className="py-3 pl-5 pr-2 align-top">
        <SeverityBadge severity={issue.severity} />
      </td>
      <td className="max-w-0 px-2 py-3 align-top">
        {href ? (
          <Link href={href} className="block truncate hover:text-accent">{title}</Link>
        ) : (
          title
        )}
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          {issue.cve && <span className="mono rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">{issue.cve}</span>}
          {issue.endpoint && <span className="mono truncate text-[11px] text-faint">{issue.endpoint}</span>}
          {issue.count > 1 && (
            <span className="rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] text-faint">{issue.count} findings merged</span>
          )}
        </div>
      </td>
      <td className="px-2 py-3 align-top">
        <div className="flex flex-wrap items-center gap-1">
          {issue.tools.map((t) => (
            <span key={t} className="mono rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">{t}</span>
          ))}
          {issue.confirmed && (
            <span className="inline-flex items-center gap-0.5 rounded-full bg-pulse-soft px-1.5 py-0.5 text-[10px] font-medium text-pulse">
              <ShieldCheck className="h-3 w-3" /> confirmed
            </span>
          )}
          {issue.attacked && (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-critical/10 px-1.5 py-0.5 text-[10px] font-semibold text-critical"
              title={`Observed under attack in production${issue.attack_count ? ` — ${issue.attack_count} event${issue.attack_count === 1 ? "" : "s"}` : ""}`}
            >
              <Flame className="h-3 w-3" /> under attack
            </span>
          )}
          {issue.live && !issue.attacked && (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-high/10 px-1.5 py-0.5 text-[10px] font-semibold text-high"
              title={issue.live_reason ? `Live: ${issue.live_reason}` : "Live-exploitable"}
            >
              <Zap className="h-3 w-3" /> live
            </span>
          )}
          {issue.in_attack_path && (
            <Link
              href="/attack-paths"
              className="inline-flex items-center gap-0.5 rounded-full bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold text-accent transition hover:bg-accent/20"
              title="This issue is a link in a cross-surface attack chain — that's why it ranks higher. See how it chains to a crown jewel."
            >
              <Spline className="h-3 w-3" /> on attack path
            </Link>
          )}
          {issue.kev && !issue.attacked && (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-critical/10 px-1.5 py-0.5 text-[10px] font-semibold text-critical"
              title="A CVE in this issue is on the CISA KEV catalog — actively exploited in the wild. Patch now (BOD 22-01)."
            >
              <Crosshair className="h-3 w-3" /> KEV
            </span>
          )}
          {issue.public_exploit && (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-high/10 px-1.5 py-0.5 text-[10px] font-medium text-high"
              title="A public exploit / PoC is published (ExploitDB / Metasploit)."
            >
              <Bug className="h-3 w-3" /> public exploit
            </span>
          )}
          {typeof issue.epss === "number" && issue.epss >= 0.5 && (
            <span
              className="mono rounded-full bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted"
              title="FIRST.org EPSS — probability this vulnerability is exploited in the next 30 days."
            >
              EPSS {Math.round(issue.epss * 100)}%
            </span>
          )}
        </div>
      </td>
      <td className="py-3 pr-5 align-top text-right">
        <div className="flex items-center justify-end gap-2">
          {!ignored && <IssueInvestigate issueKey={issue.key} title={issue.title} />}
          {!ignored && issue.finding_ids[0] && <IssueAutofix findingId={issue.finding_ids[0]} title={issue.title} />}
          <IssueActions issueKey={issue.key} ignored={ignored} />
          {href && (
            <Link href={href} className="hidden text-faint transition group-hover:text-accent sm:inline-block">
              <ArrowRight className="h-4 w-4" />
            </Link>
          )}
        </div>
      </td>
    </tr>
  );
}

function Stat({ n, label, tone }: { n: number | string; label: string; tone: string }) {
  return (
    <div className="text-right">
      <span className={`text-xl font-semibold ${tone}`}>{n}</span> <span className="text-xs text-faint">{label}</span>
    </div>
  );
}
