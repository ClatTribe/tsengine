import Link from "next/link";
import { Code2, ArrowRight, ShieldOff } from "lucide-react";
import { api } from "@/lib/api";
import { PageIntro } from "@/components/ui/page-intro";
import { SeverityBadge } from "@/components/ui/primitives";
import { RunCodeInvestigation } from "@/components/code/run-code-investigation";

export const dynamic = "force-dynamic";

// The AI Code Security Engineer (codeagent) surface — the code twin of /cloud-engineer. It reasons over the
// repository SOURCE: opening files, tracing a tainted value to its sink, measuring a leaked secret's blast
// radius, and finding the right-layer fix — the depth the whole-estate Lead can't reach from a finding
// digest. Every verdict is grounded in source the agent actually read (§10). When a repo is connected, the
// AI Security Engineer delegates to this specialist automatically during triage (the investigate_code tool).
export default async function CodeEngineerPage() {
  const { confirmed } = await api.codeInvestigation();

  return (
    <div className="space-y-8">
      <PageIntro
        icon={Code2}
        title="Code depth"
        description="The source-code specialist your AI Security Engineer delegates to for depth. A scanner tells you a rule fired at a file:line; this specialist opens the actual code, traces whether the tainted value really reaches the sink, measures a leaked secret's blast radius, and tells you which layer the fix belongs in. It separates genuinely exploitable findings from scanner noise — and every verdict is grounded in source it read, nothing invented. Confirmed-exploitable findings flow into your issues and compliance posture."
      />
      <Link href="/brief" className="-mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
        <ArrowRight className="h-3.5 w-3.5 rotate-180" /> Back to the AI Security Engineer
      </Link>

      <RunCodeInvestigation />

      {confirmed.length > 0 && (
        <section>
          <h2 className="mb-2 text-sm font-semibold text-ink">Confirmed at source ({confirmed.length})</h2>
          <p className="mb-3 text-xs text-muted">
            Findings the specialist opened the code for and confirmed are genuinely exploitable — now tracked as
            verified findings across your issues and compliance posture.
          </p>
          <div className="card divide-y divide-border">
            {confirmed.map((f) => (
              <div key={f.id} className="px-5 py-3.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded border border-critical/40 bg-critical/10 px-1.5 py-px text-[10px] font-semibold text-critical">
                    <ShieldOff className="h-3 w-3" /> EXPLOITABLE
                  </span>
                  <span className="text-sm font-medium text-ink">{f.title}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
                {f.description && <p className="mt-1 whitespace-pre-line text-sm leading-relaxed text-muted">{f.description}</p>}
                {f.endpoint && <div className="mono mt-1 truncate text-[11px] text-faint">{f.endpoint}</div>}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
