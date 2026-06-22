import Link from "next/link";
import { ShieldCheck, ArrowRight, FileText, CircleDashed } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

// Section order — most security buyers start at the trust frameworks and work outward to
// privacy / government. Anything without an explicit category falls into "Other".
const CATEGORY_ORDER = ["Security & trust", "Sector & payments", "Privacy", "Government", "Other"];

type Posture = { total: number; met: number; gap: number } | null;

export default async function CompliancePage() {
  // One batched call for every framework's posture, then merged against the full FRAMEWORKS list
  // so untracked frameworks still render (as "monitored, no gaps yet") — replaces fanning out 14
  // per-framework requests.
  const summary = await api.postureSummary();
  const byFramework = new Map(summary.frameworks.map((p) => [p.framework, { total: p.total, met: p.met, gap: p.gap } as Posture]));
  const entries = FRAMEWORKS.map((f) => ({ f, posture: byFramework.get(f) ?? null }));

  const withGaps = entries.filter((e) => (e.posture?.gap ?? 0) > 0).length;
  const tracked = entries.filter((e) => e.posture !== null).length;

  // group by category, preserving CATEGORY_ORDER then FRAMEWORKS order within a group
  const groups = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: entries.filter((e) => (FRAMEWORK_CATEGORY[e.f] ?? "Other") === cat),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-5">
      <PageIntro
        icon={ShieldCheck}
        title="Compliance"
        description={`Know exactly where you stand on SOC 2, ISO 27001, PCI, and ${FRAMEWORKS.length - 3} more — without the spreadsheet. We map your live findings to each control automatically, so your posture is always current and the evidence report is one click away.`}
        right={
          <Link
            href="/compliance/questionnaire"
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-accent/40 hover:text-ink"
          >
            <FileText className="h-3.5 w-3.5" /> Security questionnaire
          </Link>
        }
      />

      {/* coverage summary strip */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-surface px-4 py-3 text-xs">
        <span><span className="text-base font-semibold text-ink">{FRAMEWORKS.length}</span> <span className="text-muted">frameworks covered</span></span>
        <span><span className="text-base font-semibold text-ink">{tracked}</span> <span className="text-muted">with live control state</span></span>
        <span><span className={`text-base font-semibold ${withGaps > 0 ? "text-high" : "text-pulse"}`}>{withGaps}</span> <span className="text-muted">with open gaps</span></span>
      </div>

      {groups.map(({ cat, items }) => (
        <section key={cat} className="space-y-2">
          <h2 className="text-xs font-medium uppercase tracking-wider text-faint">{cat}</h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {items.map(({ f, posture }) => (
              <FrameworkCard key={f} f={f} posture={posture} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function FrameworkCard({ f, posture }: { f: string; posture: Posture }) {
  const label = FRAMEWORK_LABEL[f] ?? f;
  // No control state yet → coverage is live, nothing has mapped a gap. Show it as "ready"
  // rather than hiding it, so the full supported-framework catalog is always visible.
  if (!posture) {
    return (
      <Link href={`/compliance/${f}`} className="card group p-5 transition hover:border-border-strong animate-fade-rise">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CircleDashed className="h-4 w-4 text-faint" />
            <span className="text-sm font-medium">{label}</span>
          </div>
          <ArrowRight className="h-4 w-4 text-faint transition group-hover:text-accent" />
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3" />
        <div className="mt-2 text-xs text-faint">Monitored · no gaps mapped yet</div>
      </Link>
    );
  }

  const { total, met, gap } = posture;
  const pct = total > 0 ? Math.round((met / total) * 100) : 0;
  return (
    <Link href={`/compliance/${f}`} className="card group p-5 transition hover:border-border-strong animate-fade-rise">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className={`h-4 w-4 ${gap === 0 ? "text-pulse" : "text-muted"}`} />
          <span className="text-sm font-medium">{label}</span>
        </div>
        <ArrowRight className="h-4 w-4 text-faint transition group-hover:text-accent" />
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3">
        <div className={`h-full rounded-full ${gap === 0 ? "bg-pulse" : "bg-accent"}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-2 flex items-center justify-between text-xs">
        <span className="text-low">{met} met</span>
        <span className={gap > 0 ? "text-high" : "text-faint"}>{gap} gap</span>
      </div>
    </Link>
  );
}
