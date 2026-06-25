import { ClipboardCheck } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { SOC2Assessment } from "@/components/marketing/soc2-assessment";

export const metadata = pageMeta({
  title: "Free SOC 2 Readiness Self-Assessment for Startups | TensorShield",
  description:
    "Answer 15 plain-English questions and get your SOC 2 readiness score plus a prioritized list of the gaps to close first — free, no signup. Built for seed-stage founders.",
  path: "/soc2-readiness",
});

export default function SOC2ReadinessPage() {
  return (
    <section className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
      <div className="relative mx-auto max-w-3xl px-5 pb-24 pt-16 sm:pt-20">
        <div className="text-center">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-accent">
            <ClipboardCheck className="h-3.5 w-3.5" /> Free · no signup
          </span>
          <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            How SOC 2-ready are you?
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Fifteen plain-English questions across the controls that actually sink seed-stage companies. Get a readiness
            score and the exact gaps to close first — before you pay a consultant to find them.
          </p>
        </div>
        <div className="mt-10">
          <SOC2Assessment />
        </div>
      </div>
    </section>
  );
}
