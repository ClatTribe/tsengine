import { Presentation, Download } from "lucide-react";
import { api } from "@/lib/api";
import { Empty, SeverityBadge } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PrintButton } from "@/components/board/print-button";

export const dynamic = "force-dynamic";

// The one page a CTO takes to a board. Every number is the server's, assembled from the same
// computations as the issues list, the fix plan, the exposure trend and coverage — nothing is
// recomputed here — and the caveats render beside the numbers they bound, never in a footnote.
export default async function BoardPage() {
  const r = await api.boardReport();
  if (!r) {
    return <Empty>The board report could not be loaded.</Empty>;
  }
  const v = r.exposure.objective;
  const verdict = !v.gradeable ? "Not graded" : v.met ? "Objective met" : "Objective not met";
  const tone = !v.gradeable ? "text-muted" : v.met ? "text-pulse" : "text-high";

  return (
    <div className="space-y-5 print:space-y-3">
      <PageIntro
        icon={Presentation}
        title="Board report"
        description="One page for a board or an investor update: what is proven, whether exposure is going down against your target, what you are fixing first, and what these numbers do not cover."
      />
      <div className="flex gap-2 print:hidden">
        <PrintButton />
        <a href="/api/board-report" className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1 text-xs text-muted hover:text-ink">
          <Download className="h-3.5 w-3.5" /> Download (Markdown)
        </a>
      </div>

      <p className="text-base font-medium text-ink">{r.headline}</p>

      <section className="card space-y-1 px-4 py-3 text-sm">
        <h2 className="font-medium text-ink">Open issues</h2>
        <p className="text-muted">
          {r.proven.open_issues} open ({["critical", "high", "medium", "low"].map((s) => `${r.proven.by_severity[s] ?? 0} ${s}`).join(", ")})
        </p>
        <p className="text-muted">
          <span className="font-medium text-ink">{r.proven.exploited}</span> proven exploitable on your systems ·{" "}
          <span className="font-medium text-ink">{r.proven.kev}</span> on CISA&apos;s actively-exploited list
          {r.proven.ransomware > 0 && <> ({r.proven.ransomware} used by ransomware crews)</>}
        </p>
      </section>

      <section className="card space-y-1 px-4 py-3 text-sm">
        <h2 className="font-medium text-ink">Is exposure going down?</h2>
        <p className="text-muted">
          Last 30 days: {r.exposure.opened_30d} opened, {r.exposure.closed_30d} stopped appearing ·{" "}
          {r.exposure.confirmed_fixed} proven closed by re-test (all time)
        </p>
        <p className={tone}>
          <span className="font-medium">{verdict}</span> <span className="text-subtle">· target: {v.target}</span>
        </p>
        <p className="text-xs text-muted">{v.reason}</p>
      </section>

      <section className="card space-y-1 px-4 py-3 text-sm">
        <h2 className="font-medium text-ink">Fixing first</h2>
        {r.top_fixes.length === 0 ? (
          <p className="text-muted">Nothing open to fix.</p>
        ) : (
          <ol className="space-y-1">
            {r.top_fixes.map((s) => (
              <li key={s.key} className="flex flex-wrap items-center gap-2 text-muted">
                <span className="mono text-faint">{s.order}.</span>
                <SeverityBadge severity={s.severity} />
                <span className="text-ink">{s.title}</span>
                <span className="text-xs">closes {s.closes} across {s.assets.length} asset(s)</span>
              </li>
            ))}
          </ol>
        )}
      </section>

      <section className="card space-y-1 px-4 py-3 text-sm">
        <h2 className="font-medium text-ink">Risk decisions and coverage</h2>
        <p className="text-muted">
          {r.decisions.in_force} accepted risk(s) in force ({r.decisions.undated} with no review date) ·{" "}
          {r.decisions.lapsed} lapsed and back on the list
        </p>
        <p className="text-muted">
          {r.coverage.scanned_assets} of {r.coverage.total_assets} asset(s) scanned
          {(r.coverage.never_scanned ?? []).length > 0 && <> — never scanned: {(r.coverage.never_scanned ?? []).join(", ")}</>}
        </p>
      </section>

      <section className="space-y-1 text-xs text-subtle">
        <h2 className="font-medium text-muted">What these numbers do not say</h2>
        <ul className="list-disc pl-4">
          {r.caveats.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
