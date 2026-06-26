import Link from "next/link";
import { ArrowLeft, Layers } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { CustomFrameworkForm, DeleteCustomFramework } from "./custom-form";

export const dynamic = "force-dynamic";

export default async function CustomFrameworksPage() {
  const { custom_frameworks } = await api.customFrameworks();
  // derive each framework's posture from live findings (grounded — gaps cite real findings)
  const postures = await Promise.all(custom_frameworks.map((cf) => api.customFrameworkPosture(cf.id)));

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Link href="/compliance" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Compliance
      </Link>
      <PageIntro
        icon={Layers}
        title="Custom frameworks"
        description="Track any framework we don't ship out of the box — a regional standard, a customer's vendor questionnaire, your internal policy set. Define its controls, map each to the findings we already produce (a CWE, a scanner rule, or a built-in control), and we derive its posture from your live findings. Never a false 'compliant' — unmapped or unmatched controls stay for attestation."
        right={<CustomFrameworkForm />}
      />

      {custom_frameworks.length === 0 && (
        <div className="card p-6 text-center text-sm text-muted">No custom frameworks yet. Create one to track a standard beyond the built-in 22.</div>
      )}

      {custom_frameworks.map((cf, i) => {
        const p = postures[i];
        const cov = p?.coverage;
        const gaps = p?.controls?.filter((c) => c.state === "gap") ?? [];
        return (
          <div key={cf.id} className="card space-y-3 p-5">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-sm font-semibold">{cf.name}</div>
                {cf.description && <div className="mt-0.5 text-xs text-muted">{cf.description}</div>}
              </div>
              <DeleteCustomFramework id={cf.id} />
            </div>
            {cov && (
              <div className="rounded-lg border border-border bg-surface px-3 py-2 text-xs">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                  <span><span className="font-semibold text-ink">{cf.controls.length}</span> <span className="text-muted">controls</span></span>
                  <span><span className="font-semibold text-ink">{cov.assessable_controls}</span> <span className="text-muted">auto-evaluable</span></span>
                  <span className={gaps.length > 0 ? "text-high" : "text-faint"}><span className="font-semibold">{gaps.length}</span> gap{gaps.length === 1 ? "" : "s"}</span>
                </div>
                <div className="mt-1 text-[11px] text-faint">{cov.readiness}</div>
              </div>
            )}
            {gaps.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs uppercase tracking-wider text-muted">Gaps (from live findings)</div>
                {gaps.map((g) => (
                  <div key={g.control_id} className="flex items-center gap-2 text-xs">
                    <span className="mono rounded border border-critical/30 bg-critical/10 px-1.5 py-0.5 text-critical">{g.control_id}</span>
                    <span className="text-faint">evidenced by {g.evidence_refs?.length ?? 0} finding{(g.evidence_refs?.length ?? 0) === 1 ? "" : "s"}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
