import Link from "next/link";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import type { Issue } from "@/lib/types";
import { SeverityBadge, Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function IssuesPage() {
  const { issues, count, raw_findings, confirmed } = await api.issues();
  const collapsed = Math.max(0, raw_findings - count);

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Issues</h1>
          <p className="max-w-2xl text-xs text-muted">
            One issue, many signals. The same weakness reported by multiple scanners across your surfaces is
            collapsed into a single row — so you triage real problems, not duplicate noise.
          </p>
        </div>
        <div className="flex gap-4 text-sm">
          <Stat n={count} label="issues" tone="text-ink" />
          <Stat n={confirmed} label="multi-tool confirmed" tone="text-pulse" />
          {collapsed > 0 && <Stat n={collapsed} label="duplicates merged" tone="text-faint" />}
        </div>
      </div>

      {issues.length === 0 ? (
        <Empty>
          No open issues. As scanners run across your code, cloud, and surfaces, their findings are
          de-duplicated here into one row per real problem.
        </Empty>
      ) : (
        <div className="card p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wide text-faint">
                <th className="py-2.5 pl-5 pr-2 font-medium">Severity</th>
                <th className="px-2 py-2.5 font-medium">Issue</th>
                <th className="px-2 py-2.5 font-medium">Detected by</th>
                <th className="py-2.5 pr-5 font-medium" />
              </tr>
            </thead>
            <tbody>
              {issues.map((it) => (
                <IssueRow key={it.key} issue={it} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function IssueRow({ issue }: { issue: Issue }) {
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
        </div>
      </td>
      <td className="py-3 pr-5 align-top text-right">
        {href && (
          <Link href={href} className="inline-block text-faint transition group-hover:text-accent">
            <ArrowRight className="h-4 w-4" />
          </Link>
        )}
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
