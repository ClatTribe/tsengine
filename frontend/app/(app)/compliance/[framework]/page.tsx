import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Download, ShieldCheck, FileSignature } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function FrameworkPage({ params }: { params: Promise<{ framework: string }> }) {
  const { framework } = await params;
  const rep = await api.report(framework);
  if (!rep) notFound();

  const gaps = rep.Rows.filter((r) => r.Gap);
  const met = rep.Rows.filter((r) => !r.Gap);

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Link href="/compliance" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Compliance
      </Link>

      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">{rep.Title}</h1>
          <p className="mt-1 text-xs text-muted">
            {rep.MetCount} met · {rep.GapCount} gap
            {rep.Signer ? (
              <span className="ml-2 inline-flex items-center gap-1 text-pulse">
                <FileSignature className="h-3 w-3" /> signed
              </span>
            ) : null}
          </p>
        </div>
        <a
          href={`/api/report?framework=${framework}`}
          className="flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-border-strong hover:text-ink"
        >
          <Download className="h-3.5 w-3.5" /> Report (Markdown)
        </a>
      </div>

      <section>
        <div className="mb-2 text-xs uppercase tracking-wider text-muted">Gaps ({gaps.length})</div>
        {gaps.length === 0 ? (
          <Empty>No open gaps — every tracked control is met.</Empty>
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
    </div>
  );
}
