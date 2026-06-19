import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Download, ShieldCheck, FileSignature, Radar } from "lucide-react";
import { api } from "@/lib/api";
import { FRAMEWORK_DESC, FRAMEWORK_CATEGORY } from "@/lib/frameworks";
import { SeverityBadge, Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function FrameworkPage({ params }: { params: Promise<{ framework: string }> }) {
  const { framework } = await params;
  const rep = await api.report(framework);
  if (!rep) notFound();

  // Go marshals an empty slice as JSON `null`, so Rows is null for a not-yet-mapped
  // framework — guard it (a raw .filter would crash the page). This is exactly the case
  // the 14-framework index now links to.
  const rows = rep.Rows ?? [];
  const gaps = rows.filter((r) => r.Gap);
  const met = rows.filter((r) => !r.Gap);
  const total = rows.length;
  const pct = total > 0 ? Math.round((met.length / total) * 100) : 0;
  const assessed = total > 0;
  const desc = FRAMEWORK_DESC[framework];
  const category = FRAMEWORK_CATEGORY[framework];

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Link href="/compliance" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Compliance
      </Link>

      {/* Header */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl font-semibold">{rep.Title}</h1>
              {category && (
                <span className="rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-faint">
                  {category}
                </span>
              )}
              {rep.Signer ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-pulse-soft px-2 py-0.5 text-[10px] font-medium text-pulse">
                  <FileSignature className="h-3 w-3" /> signed
                </span>
              ) : null}
            </div>
            {desc && <p className="mt-1.5 text-sm text-muted">{desc}</p>}
          </div>
          <a
            href={`/api/report?framework=${framework}`}
            className="flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink"
          >
            <Download className="h-3.5 w-3.5" /> Report
          </a>
        </div>

        {/* Progress — only meaningful once at least one control has mapped */}
        {assessed && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted">
                {met.length} of {total} controls met
                {gaps.length > 0 && <span className="text-high"> · {gaps.length} gap{gaps.length > 1 ? "s" : ""}</span>}
              </span>
              <span className={`font-semibold ${pct === 100 ? "text-pulse" : "text-ink"}`}>{pct}%</span>
            </div>
            <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-surface-3">
              <div className={`h-full rounded-full ${gaps.length === 0 ? "bg-pulse" : "bg-accent"}`} style={{ width: `${pct}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* Not-yet-assessed state — a single, honest message (no controls have mapped to a
          finding yet). Replaces the old contradictory "every control met" + "none met". */}
      {!assessed ? (
        <div className="card flex flex-col items-center gap-3 p-10 text-center">
          <div className="grid h-11 w-11 place-items-center rounded-full bg-surface-2 text-muted">
            <Radar className="h-5 w-5" />
          </div>
          <div className="text-sm font-medium">No controls assessed yet</div>
          <p className="max-w-sm text-sm text-muted">
            TensorShield maps controls for {rep.Title} as it detects issues. As findings appear, the controls they
            touch show up here — gaps first — each backed by the finding that proves it.
          </p>
          <Link href="/findings" className="text-xs font-medium text-accent hover:underline">
            View findings →
          </Link>
        </div>
      ) : (
        <>
          <section>
            <div className="mb-2 text-xs uppercase tracking-wider text-muted">Gaps ({gaps.length})</div>
            {gaps.length === 0 ? (
              <Empty>No open gaps — every control that mapped to a finding is met.</Empty>
            ) : (
              <div className="space-y-2">
                {gaps.map((r) => (
                  <div key={r.ControlID} className="card p-4 animate-fade-rise">
                    <div className="flex items-center gap-2">
                      <span className="mono text-sm font-medium">{r.ControlID}</span>
                      <span className="rounded border border-high/30 bg-high/10 px-1.5 py-px text-[10px] font-medium text-high">GAP</span>
                    </div>
                    {r.Evidence && r.Evidence.length > 0 ? (
                      <ul className="mt-2 space-y-1.5">
                        {r.Evidence.map((e) => (
                          <li key={e.FindingID} className="flex items-center gap-2 text-sm">
                            <SeverityBadge severity={e.Severity} className="scale-90" />
                            <Link href={`/findings/${e.FindingID}`} className="truncate hover:text-accent">
                              {e.Title || e.FindingID}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="mt-1.5 text-xs text-faint">No evidence finding on record.</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>

          <section>
            <div className="mb-2 text-xs uppercase tracking-wider text-muted">Met ({met.length})</div>
            {met.length === 0 ? (
              <Empty>No controls currently met.</Empty>
            ) : (
              <div className="card flex flex-wrap gap-1.5 p-4">
                {met.map((r) => (
                  <span key={r.ControlID} className="mono inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-0.5 text-xs text-low">
                    <ShieldCheck className="h-3 w-3" /> {r.ControlID}
                  </span>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
