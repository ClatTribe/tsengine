import { Bug } from "lucide-react";
import { api } from "@/lib/api";
import { FindingsTable } from "@/components/findings/findings-table";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { severityCounts } from "@/lib/utils";

export const dynamic = "force-dynamic";

const SEV_TONE: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-faint",
};

export default async function FindingsPage() {
  // Join findings to the gated actions so the table can show what the agent is doing about
  // each one (a queued fix awaiting your approval) — not just a static list of problems.
  const [findings, approvals] = await Promise.all([api.findings(), api.approvals()]);
  const pendingByFinding = Array.from(new Set(approvals.map((a) => a.finding_id).filter(Boolean)));
  const counts = severityCounts(findings);
  const fixing = pendingByFinding.length;

  return (
    <div className="space-y-4">
      <PageIntro
        icon={Bug}
        title="Findings"
        description="The raw, detailed list of every weakness the agent has detected across your stack — each one backed by tool evidence, ranked by real-world risk, and showing what the agent is already doing about it."
      />

      <PageTabs tabs={[{ href: "/issues", label: "Issues" }, { href: "/findings", label: "All findings (raw)" }]} />
      {/* At-a-glance rollup: how bad, how many, and how many already have a fix queued — so the
          founder reads severity + workload before the row-by-row table. */}
      {findings.length > 0 && (
        <section className="grid grid-cols-3 gap-2.5 sm:grid-cols-6">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
            <div key={s} className="rounded-xl border border-border bg-surface p-3 text-center">
              <div className={`text-2xl font-semibold tracking-tight ${counts[s] ? SEV_TONE[s] : "text-faint"}`}>
                {counts[s]}
              </div>
              <div className="mt-0.5 text-[10px] uppercase tracking-wide text-faint">{s}</div>
            </div>
          ))}
          <div className="rounded-xl border border-border bg-surface p-3 text-center" title="Findings with a fix already queued for your approval">
            <div className={`text-2xl font-semibold tracking-tight ${fixing ? "text-accent" : "text-faint"}`}>{fixing}</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-wide text-faint">fixing</div>
          </div>
        </section>
      )}
      <FindingsTable findings={findings} pendingFindingIds={pendingByFinding} />
    </div>
  );
}
