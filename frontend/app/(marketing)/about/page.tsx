import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

import { ArrowRight, Target, Heart, Sparkles } from "lucide-react";

export const metadata = pageMeta({
  title: "About — TensorShield",
  description: "Security shouldn't require a security hire. We're building the fractional security team every SMB deserves.",
  path: "/about",
});

const VALUES = [
  { icon: Target, t: "Outcomes, not dashboards", d: "We measure ourselves by issues fixed and audits passed — not by how many charts we can show you." },
  { icon: Heart, t: "Honest by default", d: "We never claim a posture we can't prove. Grounded findings and signed evidence aren't features — they're the whole point." },
  { icon: Sparkles, t: "Automate the toil, keep the judgment", d: "The agent does the relentless work; you make the calls that need a human. That balance is the product." },
];

export default function About() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Our mission</span>
          <h1 className="mt-3 text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
            Security shouldn&apos;t require a security hire.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Small and growing companies are the most targeted and the least resourced. A first security hire costs more
            than most can spare — so the work doesn&apos;t happen, and the risk piles up. We built TensorShield to change
            that: a fractional security team that runs itself, and asks for you only when it counts.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-8">
        <div className="grid gap-4 sm:grid-cols-3">
          {VALUES.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-6">
              <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                <FeatureIcon name={Icon.displayName} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-base font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">Built on a simple belief.</h2>
          <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
            The best security teams automate everything they can and reserve human attention for what truly needs it.
            We&apos;re packaging that team into software so every company can have one — not just the ones who can afford to
            hire it.
          </p>
          <Link href="/signup" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
