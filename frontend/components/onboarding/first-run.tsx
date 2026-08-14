import Link from "next/link";
import { Target, Plug, ShieldCheck, ArrowRight, Route, CheckCircle2 } from "lucide-react";
import { CONNECTORS, CATEGORY_LABEL, type ConnectorCategory } from "@/lib/connectors";
import { ProviderIcon } from "@/components/brand/provider-icon";
import { ServiceModelPicker } from "@/components/onboarding/service-model-picker";

// The three steps are the product's actual spine, and they are the same whichever door you came in
// through: connect, we find what is real, a human approves the change. Framing them around one outcome
// made the other one look like a different product.
const STEPS = [
  { Icon: Plug, title: "Connect your systems", body: "Code, cloud, identity, SaaS — OAuth, read-only. We only assess what you connect." },
  { Icon: Route, title: "We find what's real", body: "Scanners plus correlation across surfaces, so a code leak and a cloud role are one issue. Every finding cites its evidence." },
  { Icon: CheckCircle2, title: "You approve the fix", body: "The agent prepares the change and the evidence; nothing is applied until a named human signs off." },
];

// The cold-start surface, shown on the Overview when a tenant has no connections yet.
//
// IT OFFERS BOTH DOORS, because the product has two co-equal outcomes and the customer arrived through
// one of them. This used to lead with a single compliance CTA, which was right for the original
// SOC-2-founder ICP and wrong now: the homepage sells "one leaked secret is all it takes to reach your
// cloud root", so a security buyer signed up for attack paths and the first screen after signup asked
// them to pick an audit framework. That discontinuity reads as landing in the wrong product.
//
// Neither door is the default. They are ordered security-first only because that is what the current
// homepage promises; the compliance card is the same weight, not a secondary link. The honest and
// genuinely useful thing to say is that both run on the SAME connections — so whichever is urgent, the
// other is mostly done once systems are connected. That is the actual argument for buying one product
// instead of Wiz and Vanta, and the first run is the right place to make it.
export function FirstRun({ serviceModel }: { serviceModel?: string }) {
  return (
    <div className="mx-auto max-w-3xl space-y-8 py-6">
      <div className="text-center">
        <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-accent/40 bg-accent-soft text-accent">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <h1 className="text-2xl font-semibold">Find what an attacker can reach — and prove it to your auditor</h1>
        <p className="mx-auto mt-2 max-w-lg text-sm text-muted">
          Both run on the same connections. Start with whichever one is urgent — once your systems are
          connected, the other is mostly done.
        </p>
      </div>

      {/* The two doors, co-equal. Security first because that is what the homepage promises; the
          compliance card carries the same visual weight, not a secondary link. */}
      <div className="grid gap-3 sm:grid-cols-2">
        <Link
          href="/assets"
          className="group flex flex-col gap-2 rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 transition hover:border-accent"
        >
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent text-white shadow-sm">
            <Route className="h-5 w-5" />
          </span>
          <span className="mt-1 flex items-center gap-1.5 text-sm font-semibold text-ink">
            See your attack paths
            <ArrowRight className="h-4 w-4 text-accent transition group-hover:translate-x-0.5" />
          </span>
          <span className="text-xs leading-relaxed text-muted">
            Connect code and cloud. The AI security engineer traces what a leaked key or an exposed
            service actually reaches, and prepares the fix.
          </span>
        </Link>

        <Link
          href="/compliance/scope"
          className="group flex flex-col gap-2 rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 transition hover:border-accent"
        >
          <span className="grid h-11 w-11 place-items-center rounded-xl bg-accent text-white shadow-sm">
            <Target className="h-5 w-5" />
          </span>
          <span className="mt-1 flex items-center gap-1.5 text-sm font-semibold text-ink">
            Get audit-ready
            <ArrowRight className="h-4 w-4 text-accent transition group-hover:translate-x-0.5" />
          </span>
          <span className="text-xs leading-relaxed text-muted">
            Pick the frameworks you&rsquo;re pursuing. Your live findings map to each control with signed
            evidence — and honest coverage, never a false &ldquo;compliant&rdquo;.
          </span>
        </Link>
      </div>

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

      {/* Service model — set who owns the human-in-the-loop up front (default self-serve), so a managed
          or MSP tenant isn't silently defaulted. */}
      <ServiceModelPicker current={serviceModel} />

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
                  <p className="text-[11px] leading-relaxed text-faint">{c.evidence}</p>
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
