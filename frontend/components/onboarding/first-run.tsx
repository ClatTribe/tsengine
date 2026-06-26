import Link from "next/link";
import { Target, Plug, ShieldCheck, ArrowRight, FileCheck2 } from "lucide-react";
import { CONNECTORS, CATEGORY_LABEL, type ConnectorCategory } from "@/lib/connectors";
import { ProviderIcon } from "@/components/brand/provider-icon";

// Compliance-led onboarding (the founder ICP came for SOC 2 / ISO / HIPAA, not a scanner) — so we lead
// with the goal, like Sprinto/Vanta: 1) tell us your framework, 2) connect your systems, 3) see your
// gaps + signed evidence. Each step is honest about coverage (no false-compliant).
const STEPS = [
  { Icon: Target, title: "Set your compliance goal", body: "Pick the frameworks you're pursuing — SOC 2, ISO 27001, HIPAA, PCI, and 18 more." },
  { Icon: Plug, title: "Connect your systems", body: "Identity, cloud, code, SaaS — one click of OAuth. We only assess what you connect." },
  { Icon: FileCheck2, title: "See gaps + signed evidence", body: "Your live findings map to each control — with honest coverage, never a false 'compliant'." },
];

// The cold-start surface: shown on the Overview when a tenant has no connections yet. A self-serve SMB
// product lives or dies on this first run — lead the founder straight into their compliance goal.
export function FirstRun() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-6">
      <div className="text-center">
        <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-accent/40 bg-accent-soft text-accent">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <h1 className="text-2xl font-semibold">Get audit-ready — without a security hire</h1>
        <p className="mx-auto mt-2 max-w-md text-sm text-muted">
          Tell us which framework you&rsquo;re pursuing, connect your systems, and the agent maps your live
          findings to every control — preparing fixes and signed, auditor-ready evidence.
        </p>
      </div>

      {/* Primary CTA — the compliance goal first (the founder ICP's actual job). */}
      <Link
        href="/compliance/scope"
        className="group flex items-center gap-4 rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 transition hover:border-accent"
      >
        <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
          <Target className="h-5 w-5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-ink">Start with your compliance goal</span>
          <span className="block text-xs leading-relaxed text-muted">A few questions decide which frameworks apply, then we show exactly what to connect.</span>
        </span>
        <ArrowRight className="h-5 w-5 shrink-0 text-accent transition group-hover:translate-x-0.5" />
      </Link>

      {/* How it works */}
      <div className="grid gap-3 sm:grid-cols-3">
        {STEPS.map(({ Icon, title, body }, i) => (
          <div key={title} className="card p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="grid h-7 w-7 place-items-center rounded-lg border border-border bg-surface-2 text-accent">
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="text-[11px] font-medium text-faint">STEP {i + 1}</span>
            </div>
            <div className="text-sm font-medium">{title}</div>
            <div className="mt-0.5 text-xs leading-relaxed text-muted">{body}</div>
          </div>
        ))}
      </div>

      {/* Quick connect — step 2, ready to go the moment they've set a goal. */}
      <div className="space-y-5">
        <div className="text-[11px] uppercase tracking-wider text-faint">Or connect a system now</div>
        {(["code", "identity"] as ConnectorCategory[]).map((cat) => (
          <div key={cat}>
            <div className="mb-2 text-[11px] uppercase tracking-wider text-faint">{CATEGORY_LABEL[cat]}</div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {CONNECTORS.filter((c) => c.category === cat).map((c) => (
                <a
                  key={c.kind}
                  href={`/connect/${c.kind}`}
                  className="group card flex flex-col gap-2 p-4 transition hover:border-accent/40 hover:bg-surface-2"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="grid h-8 w-8 place-items-center rounded-lg border border-border bg-surface-2 text-ink">
                      <ProviderIcon kind={c.kind} className="h-4 w-4" />
                    </span>
                    <span className="flex-1 text-sm font-medium">{c.label}</span>
                    <ArrowRight className="h-4 w-4 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
                  </div>
                  <p className="text-xs leading-relaxed text-muted">{c.monitors}</p>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="text-center">
        <Link href="/assets" className="text-xs text-accent transition hover:underline">
          See all connection options →
        </Link>
      </div>
    </div>
  );
}
