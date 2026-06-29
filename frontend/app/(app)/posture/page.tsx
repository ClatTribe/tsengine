import { ShieldCheck, Building2, Laptop, CloudCog } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";

export const dynamic = "force-dynamic";

const SOURCE_ICON: Record<string, typeof Building2> = {
  tprm: Building2,
  deviceposture: Laptop,
  clouddrift: CloudCog,
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default async function PosturePage() {
  const { total, sources } = await api.postureSources();

  return (
    <div className="space-y-8">
      <PageIntro
        icon={ShieldCheck}
        title="Vendors & devices"
        description="Risk across the asset classes a pure scanner misses — your vendors, your employee devices, and changes to your cloud since the last baseline. Each is assessed against SOC 2 / CIS / NIST / GDPR controls and flows into the same issues and compliance posture as every other finding."
      />

      <PageTabs tabs={[{ href: "/coverage", label: "Test coverage" }, { href: "/posture", label: "Asset posture" }]} />

      {total === 0 ? (
        <Empty>
          No posture risks yet. Post a vendor inventory to <code>/v1/tprm/ingest</code>, a device inventory to{" "}
          <code>/v1/devices/ingest</code>, or two cloud snapshots to <code>/v1/cloud/drift</code> to assess vendor,
          device, and drift posture. A well-managed estate shows nothing here.
        </Empty>
      ) : (
        <div className="space-y-6">
          {sources.map((s) => {
            const Icon = SOURCE_ICON[s.key] ?? ShieldCheck;
            const findings = [...s.findings].sort(
              (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
            );
            return (
              <section key={s.key} className="rounded-2xl border border-border bg-surface">
                <header className="flex items-start gap-3 border-b border-border px-5 py-4">
                  <div className="mt-0.5 rounded-lg border border-border bg-surface-muted p-2">
                    <Icon className="h-5 w-5 text-muted" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h2 className="font-semibold">{s.label}</h2>
                      <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted">{s.count}</span>
                    </div>
                    <p className="mt-1 text-sm text-muted">{s.about}</p>
                  </div>
                </header>
                {s.count === 0 ? (
                  <p className="px-5 py-4 text-sm text-muted">No risks found — this posture source is clean.</p>
                ) : (
                  <ul className="divide-y divide-border">
                    {findings.map((f) => (
                      <li key={f.id} className="flex items-start gap-3 px-5 py-3">
                        <SeverityBadge severity={f.severity} />
                        <div className="min-w-0 flex-1">
                          <p className="font-medium">{f.title}</p>
                          {f.description ? <p className="mt-0.5 text-sm text-muted">{f.description}</p> : null}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
