import Link from "next/link";
import { ShieldCheck, ArrowRight, FileText, CircleDashed, Plug, CircleCheck, Circle, Layers, Target, FileSignature } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "@/lib/api";
import { ASSET_TYPE_LABEL } from "@/lib/connectors";
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
  const [summary, readiness, byAsset] = await Promise.all([api.postureSummary(), api.complianceReadiness(), api.complianceByAsset()]);
  const assetRows = byAsset.assets.filter((a) => a.attributed); // only assets we can ground a signal on
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
            <Link
              href="/audits"
              className="inline-flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-muted transition hover:border-accent/40 hover:text-ink"
              title="We don't certify you — an independent auditor attests. Start that engagement here."
            >
              <FileSignature className="h-3.5 w-3.5" /> Get attested
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
            <Link href="/assets" className="mt-3 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
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
              {/* Make the manual areas actionable — route the founder (or their HITL expert) to where these
                  actually get closed, instead of a dead-end list. This is the two-model HITL top layer. */}
              <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border/40 pt-3">
                <span className="text-[11px] font-medium text-muted">Close these:</span>
                <Link href="/program" className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-0.5 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink">
                  <FileText className="h-3 w-3" /> 1. Document a policy
                </Link>
                <Link href="/audits" className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-0.5 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink">
                  <FileSignature className="h-3 w-3" /> 2. Get an auditor to attest
                </Link>
                <Link href="/risks" className="inline-flex items-center gap-1 rounded-md border border-border bg-surface px-2 py-0.5 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink">
                  <CircleDashed className="h-3 w-3" /> or accept the risk
                </Link>
              </div>
              <p className="mt-1.5 text-[11px] text-faint">
                Your team closes these — or, on a managed plan, your MSP&apos;s expert or our hired expert documents
                the evidence and signs off on your behalf (named, accountable).
              </p>
            </div>
          )}
        </section>
      )}

      {/* Per-asset compliance — "is THIS asset compliant?" Grounded: only assets a finding's endpoint ties
          to appear; never a fabricated per-asset verdict, never a bare "compliant". */}
      {assetRows.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-xs font-medium uppercase tracking-wider text-faint">
            By asset <span className="ml-1 text-faint/70">· {byAsset.attributed} of {byAsset.total} with an asset-level signal</span>
          </h2>
          <div className="overflow-hidden rounded-lg border border-border">
            {assetRows.map((a) => (
              <div key={a.asset_id} className="flex items-center gap-3 border-b border-border/60 bg-surface px-4 py-2.5 text-sm last:border-b-0">
                <span className="mono min-w-0 flex-1 truncate text-ink" title={a.target}>{a.target || a.asset_id}</span>
                <span className="hidden shrink-0 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-faint sm:inline">{ASSET_TYPE_LABEL[a.type] ?? a.type}</span>
                {a.gap_controls > 0 ? (
                  <span className="shrink-0 text-xs text-high">{a.gap_controls} control gap{a.gap_controls === 1 ? "" : "s"}{a.frameworks.length > 0 ? ` · ${a.frameworks.length} framework${a.frameworks.length === 1 ? "" : "s"}` : ""}</span>
                ) : (
                  <span className="shrink-0 text-xs text-faint">no automated gaps</span>
                )}
              </div>
            ))}
          </div>
          <p className="text-[11px] text-faint">Per-asset signal is grounded in findings tied to each asset; assets with no tied finding aren&apos;t shown and are never marked compliant.</p>
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

      <p className="text-[11px] leading-relaxed text-faint">
        <span className="font-medium text-muted">How control mappings are derived.</span> Each finding maps to a
        framework control only where a real control nexus exists (never assumed) — the crosswalk is curated in‑house
        from the published framework standards (NIST 800‑53, PCI‑DSS, ISO 27001, …), the same way the leading GRC
        platforms maintain theirs. The mappings are additionally cross‑referenceable against{" "}
        <span className="font-medium text-muted">OpenCRE</span> (OWASP&apos;s open Common Requirement Enumeration);
        run <code className="mono rounded bg-surface-2 px-1 py-0.5 text-[10px]">tsengine corpus compliance-provenance</code>{" "}
        for the OSS‑corroborated vs in‑house‑only split. Threat‑intel feeds (CISA KEV, FIRST.org EPSS, Exploit‑DB) are
        sourced live from OSS, pinned per scan.
      </p>
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
