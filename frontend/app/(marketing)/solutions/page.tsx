import Link from "next/link";
import { ArrowRight } from "lucide-react";

import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { LANES } from "@/lib/solutions";

export const metadata = pageMeta({
  title: "Solutions — by Scenario, Surface or Tool",
  description:
    "Three ways in: the situation that made you look, the surface you need covered, or how we compare with what you use today. Start wherever you actually are.",
  path: "/solutions",
});

// The Solutions hub deliberately does NOT restate the pitch. Every other page already opens with
// "here is a problem, here is our solution", which only lands if the visitor shares our framing.
// This page's whole job is to let someone route themselves by whichever question they actually
// walked in with — and to make the 14 pages that were previously unreachable from the nav findable.
export default function Solutions() {
  return (
    <>
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Solutions</span>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">Where do you want to start?</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Nobody buys security because of a feature list. Pick whichever of these sounds like your
            actual situation — they all end up at the same engine, from a different door.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-5xl px-5 pb-24">
        {LANES.map((lane, i) => (
          <section key={lane.slug} id={lane.slug} className={i === 0 ? "" : "mt-16"}>
            <div className="flex items-baseline gap-3">
              <span className="text-xs font-semibold text-faint">{String(i + 1).padStart(2, "0")}</span>
              <h2 className="text-2xl font-semibold tracking-tight">{lane.title}</h2>
            </div>
            <p className="mt-2 max-w-2xl text-[15px] leading-relaxed text-muted">{lane.blurb}</p>

            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {lane.items.map((it) => (
                <Link
                  key={it.href}
                  href={it.href}
                  className="card group flex items-start gap-3 px-4 py-3.5 transition hover:border-accent/50"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 text-sm font-medium">
                      <span className="truncate">{it.label}</span>
                      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent" />
                    </div>
                    {/* The buyer's own words, not our positioning — so they recognise themselves. */}
                    <p className="mt-1 text-[13px] leading-relaxed text-muted">{it.prompt}</p>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        ))}

        {/* An honest exit for the visitor whose situation isn't listed — better than forcing a
            not-quite-right lane and losing them. */}
        <section className="mt-16 rounded-2xl border border-border bg-surface px-6 py-7 text-center">
          <h2 className="text-lg font-semibold">None of these quite fit?</h2>
          <p className="mx-auto mt-2 max-w-xl text-[15px] leading-relaxed text-muted">
            Tell us the situation in your own words and we&rsquo;ll say plainly whether this is the right
            tool — including when it isn&rsquo;t.
          </p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/demo"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white transition hover:opacity-90"
            >
              Talk to us <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/scan"
              className="inline-flex items-center gap-2 rounded-xl border border-border bg-bg px-5 py-2.5 text-sm font-medium transition hover:border-accent/50"
            >
              Or just scan your domain — free, no signup
            </Link>
          </div>
        </section>
      </div>
    </>
  );
}
