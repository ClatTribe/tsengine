import Link from "next/link";
import { ShieldCheck, ArrowRight, FileText, CircleDashed, Plug, CircleCheck, Circle, Layers, Target } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

// Section order — most security buyers start at the trust frameworks and work outward to
// privacy / government. Anything without an explicit category falls into "Other".
const CATEGORY_ORDER = ["Security & trust", "Sector & payments", "Privacy", "Government", "AI governance", "Other"];

type Posture = { total: number; met: number; gap: number; assessable: number; notAssessed: number; coveragePct: number; readiness: string } | null;

export default async function CompliancePage() {
  // One batched call for every framework's posture, then merged against the full FRAMEWORKS list
  // so untracked frameworks still render (as "monitored, no gaps yet") — replaces fanning out 14
  // per-framework requests.
  const [summary, readiness] = await Promise.all([api.postureSummary(), api.complianceReadiness()]);
  const byFramework = new Map(summary.frameworks.map((p) => [p.framework, { total: p.total, met: p.met, gap: p.gap, assessable: p.assessable, notAssessed: p.not_assessed, coveragePct: p.coverage_pct, readiness: p.readiness } as Posture]));
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
          <div className="flex shrink-0 items-center gap-2">
            <Link
              href="/compliance/scope"
              className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-1.5 text-xs font-medium text-accent transition hover:border-accent"
            >
              <Target className="h-3.5 w-3.5" /> Set scope
            </Link>
            <Link
              href="/compliance/custom"
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-accent/40 hover:text-ink"
            >
              <Layers className="h-3.5 w-3.5" /> Custom frameworks
            </Link>
            <Link
              href="/compliance/questionnaire"
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-accent/40 hover:text-ink"
            >
              <FileText className="h-3.5 w-3.5" /> Security questionnaire
            </Link>
          </div>
        }
      />

      {/* coverage summary strip */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-surface px-4 py-3 text-xs">
        <span><span className="text-base font-semibold text-ink">{FRAMEWORKS.length}</span> <span className="text-muted">frameworks covered</span></span>
        <span><span className="text-base font-semibold text-ink">{tracked}</span> <span className="text-muted">with live control state</span></span>
        <span><span className={`text-base font-semibold ${withGaps > 0 ? "text-high" : "text-pulse"}`}>{withGaps}</span> <span className="text-muted">with open gaps</span></span>
      </div>

      {/* Connect-this-first readiness checklist — what the customer must integrate before the posture can
          be read as anything close to compliant (the no-false-compliant scoping ask). */}
      {readiness.recommended > 0 && (
        <section className="rounded-lg border border-accent/30 bg-accent-soft/20 p-4">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Plug className="h-4 w-4 text-accent" />
            What we can assess for compliance
            <span className="ml-auto text-xs text-muted">{readiness.connected} of {readiness.recommended} connected</span>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-muted">{readiness.note}</p>
          <div className="mt-3 grid gap-1.5 sm:grid-cols-2">
            {readiness.integrations.map((it) => (
              <div key={it.category} className="flex items-start gap-2 text-xs">
                {it.connected ? <CircleCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-pulse" /> : <Circle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-faint" />}
                <span>
                  <span className={it.connected ? "text-ink" : "text-muted"}>{it.label}</span>
                  {!it.connected && <span className="text-faint"> — connect {it.connectors}</span>}
                  <span className="block text-[11px] text-faint">{it.unlocks}</span>
                </span>
              </div>
            ))}
          </div>
          {readiness.connected < readiness.recommended && (
            <Link href="/connect" className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
              Connect a system <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          )}

          {readiness.manual_areas?.length > 0 && (
            <div className="mt-4 border-t border-border/60 pt-3">
              <div className="text-xs font-medium text-muted">Not automated — these require manual evidence + auditor attestation</div>
              <div className="mt-2 grid gap-1.5 sm:grid-cols-2">
                {readiness.manual_areas.map((m) => (
                  <div key={m.category} className="flex items-start gap-2 text-xs">
                    <CircleDashed className="mt-0.5 h-3.5 w-3.5 shrink-0 text-faint" />
                    <span>
                      <span className="text-muted">{m.label}</span>
                      <span className="block text-[11px] text-faint">{m.unlocks}</span>
                    </span>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] text-faint">We never mark these met from a scan — so the posture is never a false &ldquo;compliant&rdquo;.</p>
            </div>
          )}
        </section>
      )}

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

  const { gap, assessable, notAssessed, coveragePct, readiness } = posture;
  // The bar is ASSESSMENT COVERAGE (how much we've evaluated), NOT a compliance score — so a clean-but-
  // thin posture never looks "done". gap===0 is shown neutrally (no green "certified" checkmark), because
  // "no automated gaps" is not "compliant" (the no-false-compliant rule).
  const pct = Math.round(coveragePct);
  return (
    <Link href={`/compliance/${f}`} className="card group p-5 transition hover:border-border-strong animate-fade-rise">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className={`h-4 w-4 ${gap > 0 ? "text-high" : "text-muted"}`} />
          <span className="text-sm font-medium">{label}</span>
        </div>
        <ArrowRight className="h-4 w-4 text-faint transition group-hover:text-accent" />
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3" title={`${pct}% of assessable controls assessed`}>
        <div className={`h-full rounded-full ${gap > 0 ? "bg-accent" : "bg-low"}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-2 flex items-center justify-between text-xs">
        <span className="text-low">{assessable > 0 ? `${pct}% assessed` : "coverage n/a"}</span>
        <span className={gap > 0 ? "text-high" : "text-faint"}>{gap} gap{gap === 1 ? "" : "s"}</span>
      </div>
      {notAssessed > 0 && <div className="mt-1 text-[11px] text-faint">{notAssessed} control{notAssessed === 1 ? "" : "s"} not yet assessed · not a certification</div>}
      <div className="sr-only">{readiness}</div>
    </Link>
  );
}
