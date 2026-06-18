import Link from "next/link";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL } from "@/lib/api";
import { Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function CompliancePage() {
  const data = await Promise.all(
    FRAMEWORKS.map(async (f) => {
      const cs = await api.posture(f);
      if (cs.length === 0) return null;
      const gap = cs.filter((c) => c.state === "gap").length;
      return { f, total: cs.length, met: cs.length - gap, gap };
    }),
  );
  const frameworks = data.filter(Boolean) as { f: string; total: number; met: number; gap: number }[];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Compliance</h1>
        <p className="text-xs text-muted">Control posture, grounded in real findings — with a signed, attachable report.</p>
      </div>

      {frameworks.length === 0 ? (
        <Empty>No control state yet — findings map to controls as they&apos;re detected.</Empty>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {frameworks.map(({ f, total, met, gap }) => {
            const pct = total > 0 ? Math.round((met / total) * 100) : 0;
            return (
              <Link key={f} href={`/compliance/${f}`} className="card group p-5 transition hover:border-border-strong animate-fade-rise">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className={`h-4 w-4 ${gap === 0 ? "text-pulse" : "text-muted"}`} />
                    <span className="text-sm font-medium">{FRAMEWORK_LABEL[f] ?? f}</span>
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
          })}
        </div>
      )}
    </div>
  );
}
