"use client";

import { useEffect, useState } from "react";
import { Layers, GitMerge, Filter, Flame, Crosshair, ListChecks, ChevronRight } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// Prioritize — USP #1: "we prioritize the alerts so you don't have to." A live, horizontal funnel:
// an active-stage pointer steps left→right (the agent triaging), counts narrow, flowing dots stream
// between stages. Every stage is a real, shipped mechanism (§10); the counts are illustrative
// (labelled as such), not a measured claim.
const STAGES = [
  { icon: Layers, label: "Raw signals", count: "1,200+", note: "30+ scanners, every surface", tone: "in" as const },
  { icon: GitMerge, label: "Collapse duplicates", count: "310", note: "many alerts → one issue", tone: "mid" as const },
  { icon: Filter, label: "Drop false positives", count: "180", note: "fingerprint + confidence", tone: "mid" as const },
  { icon: Flame, label: "Rank by exploitability", count: "40", note: "KEV · EPSS · reachability", tone: "mid" as const },
  { icon: Crosshair, label: "Weight by blast radius", count: "12", note: "data-tier · exposed · attacked", tone: "mid" as const },
  { icon: ListChecks, label: "What matters", count: "6", note: "in priority order", tone: "out" as const },
];

export function Prioritize() {
  const [active, setActive] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setActive((a) => (a + 1) % STAGES.length), 1100);
    return () => clearInterval(t);
  }, []);

  return (
    <section className="border-y border-border bg-surface">
      <div className="mx-auto max-w-6xl px-5 py-16">
        <Reveal className="mx-auto mb-9 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Less noise</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
            We prioritize the alerts, so you don&apos;t have to.
          </h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Every raw alert runs through the same funnel a senior engineer would — live, on every scan. What&apos;s
            left is the short list that actually matters, in order.
          </p>
        </Reveal>

        <Reveal delay={80} className="overflow-x-auto pb-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          <div className="flex min-w-max items-stretch gap-1.5 sm:justify-center">
            {STAGES.map((s, i) => {
              const Icon = s.icon;
              const lit = i <= active; // everything up to the pointer is "processed"
              const isActive = i === active;
              const isOut = s.tone === "out";
              return (
                <div key={s.label} className="flex items-stretch gap-1.5">
                  <div
                    className={[
                      "w-[8.6rem] shrink-0 rounded-xl border p-3 transition-all duration-500",
                      isActive
                        ? "border-accent bg-accent-soft/60 shadow-card-hover -translate-y-0.5"
                        : lit
                          ? isOut
                            ? "border-accent/50 bg-accent-soft/30"
                            : "border-border bg-surface"
                          : "border-border bg-surface opacity-55",
                    ].join(" ")}
                  >
                    <div className="flex items-center justify-between">
                      <span
                        className={[
                          "grid h-7 w-7 place-items-center rounded-lg transition-colors duration-500",
                          isActive || isOut ? "bg-accent text-white" : lit ? "bg-accent-soft text-accent" : "bg-surface-2 text-muted",
                        ].join(" ")}
                      >
                        <Icon className="h-3.5 w-3.5" />
                      </span>
                      <span
                        className={[
                          "tabular-nums text-base font-semibold transition-colors duration-500",
                          isOut ? "text-accent" : isActive ? "text-ink" : "text-muted",
                        ].join(" ")}
                      >
                        {s.count}
                      </span>
                    </div>
                    <div className="mt-2 text-xs font-semibold leading-snug text-ink">{s.label}</div>
                    <div className="mt-0.5 text-[11px] leading-snug text-muted">{s.note}</div>
                  </div>

                  {/* connector with a flowing dot — except after the last stage */}
                  {i < STAGES.length - 1 && (
                    <div className="flex w-6 shrink-0 items-center justify-center self-center">
                      <div className="relative h-px w-full bg-gradient-to-r from-border via-accent/40 to-border">
                        <span
                          className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_8px_rgba(79,70,229,0.6)] animate-flow-x"
                          style={{ animationDelay: `${i * 0.4}s` }}
                        />
                      </div>
                      <ChevronRight className="absolute h-3.5 w-3.5 text-faint/0" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Reveal>

        <p className="mt-5 text-center text-xs text-faint">
          Illustrative funnel — your numbers vary. The mechanisms are real: dedup into one confirmed issue ·
          fingerprint + confidence FP filter · KEV/EPSS/reachability ranking · data-tier &amp; under-attack weighting.
        </p>
      </div>
    </section>
  );
}
