import { Layers, GitMerge, Filter, Flame, Crosshair, ArrowDown, ListChecks } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// Prioritize — USP #1: "we prioritize the alerts so you don't have to." Shows the noise-reduction
// funnel as concrete, shipped mechanisms (§10): dedup into issues, drop false positives, rank by
// real exploitability (KEV/EPSS/reachability), weight by blast radius (data tier / internet-exposed
// / under active attack). Pairs with the Differentiator section (USP #2: alert → fix).
const STEPS = [
  {
    icon: GitMerge,
    t: "Collapse the duplicates",
    d: "Many alerts about the same thing become one issue — and it's marked Confirmed when two or more independent tools agree.",
  },
  {
    icon: Filter,
    t: "Cut the false positives",
    d: "A fingerprint filter and a per-finding confidence score drop the noise that isn't real, before it ever reaches you.",
  },
  {
    icon: Flame,
    t: "Rank by real exploitability",
    d: "CISA KEV (exploited in the wild), EPSS probability, network reachability and public-PoC availability decide what's actually dangerous — not just severity.",
  },
  {
    icon: Crosshair,
    t: "Weight by blast radius",
    d: "Customer-data tier, internet-exposed, and seen-under-active-attack-in-production push the issues that threaten your crown jewels to the top.",
  },
];

export function Prioritize() {
  return (
    <section className="border-y border-border bg-surface">
      <div className="mx-auto max-w-5xl px-5 py-16">
        <Reveal className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Less noise</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
            We prioritize the alerts, so you don&apos;t have to.
          </h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Scanners bury you in findings. TensorShield runs every raw alert through the same funnel a senior
            engineer would — so what&apos;s left is the short list that actually matters, in order.
          </p>
        </Reveal>

        <Reveal delay={90} className="mx-auto max-w-2xl">
          {/* funnel: raw → filters → the few that matter */}
          <div className="flex items-center gap-3 rounded-xl border border-border bg-bg px-4 py-3">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface-2 text-muted">
              <Layers className="h-4 w-4" />
            </span>
            <span className="text-sm text-muted">
              Raw output from <span className="font-medium text-ink">30+ scanners</span> across every surface
            </span>
          </div>

          {STEPS.map(({ icon: Icon, t, d }) => (
            <div key={t}>
              <div className="flex justify-center py-1.5">
                <ArrowDown className="h-4 w-4 text-faint" />
              </div>
              <div className="flex items-start gap-3 rounded-xl border border-border bg-surface px-4 py-3 shadow-card">
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-ink">{t}</div>
                  <p className="mt-0.5 text-sm leading-relaxed text-muted">{d}</p>
                </div>
              </div>
            </div>
          ))}

          <div className="flex justify-center py-1.5">
            <ArrowDown className="h-4 w-4 text-accent" />
          </div>
          <div className="flex items-center gap-3 rounded-xl border-2 border-accent bg-accent-soft/40 px-4 py-3.5">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent text-white shadow-sm">
              <ListChecks className="h-4 w-4" />
            </span>
            <span className="text-sm font-medium text-ink">
              The handful that actually matter — in priority order. Start at the top.
            </span>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
