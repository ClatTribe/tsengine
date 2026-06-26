import Link from "next/link";
import { ArrowRight, Check, Scale, CheckCircle2 } from "lucide-react";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import type { CompetitorPage } from "@/lib/competitors";

// ComparisonPage renders an honest, SEO-clean "TensorShield vs. <Competitor>" page from one CompetitorPage
// entry — hero, a genuine "what they're great at" section (§10: never fabricate a weakness), a side-by-side
// table, our real differentiators, an honest "choose them / choose us", an FAQ (with FAQPage JSON-LD), CTA.
export function ComparisonPage({ data }: { data: CompetitorPage }) {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Scale className="h-3.5 w-3.5 text-accent" /> {data.category}
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">{data.h1}</h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">{data.sub}</p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Talk to an expert
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">An honest comparison — we name what {data.name} does well before our differences.</p>
        </div>
      </section>

      {/* What they're great at (honest) */}
      <section className="mx-auto max-w-3xl px-5 pb-4 pt-6">
        <div className="rounded-2xl border border-border bg-surface p-6">
          <h2 className="text-lg font-semibold tracking-tight text-ink">What {data.name} is genuinely good at</h2>
          <ul className="mt-4 space-y-2.5">
            {data.theirStrengths.map((s) => (
              <li key={s} className="flex items-start gap-2.5 text-sm leading-relaxed text-muted">
                <Check className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {s}
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-faint">We&apos;re not here to bash a good product — just to be clear about where we&apos;re different.</p>
        </div>
      </section>

      {/* Comparison table */}
      <section className="mx-auto max-w-4xl px-5 py-14">
        <div className="mx-auto mb-8 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Side by side</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">TensorShield vs. {data.name}</h2>
        </div>
        <div className="overflow-hidden rounded-2xl border border-border">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border bg-surface">
                <th className="px-4 py-3 font-semibold text-muted">Capability</th>
                <th className="px-4 py-3 font-semibold text-accent">TensorShield</th>
                <th className="px-4 py-3 font-semibold text-ink">{data.name}</th>
              </tr>
            </thead>
            <tbody>
              {data.rows.map((r, i) => (
                <tr key={r.dim} className={i % 2 ? "bg-surface/40" : ""}>
                  <td className="border-t border-border px-4 py-3 font-medium text-ink">{r.dim}</td>
                  <td className="border-t border-border px-4 py-3 text-muted">
                    <span className="inline-flex items-start gap-1.5"><Check className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {r.us}</span>
                  </td>
                  <td className="border-t border-border px-4 py-3 text-muted">{r.them}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-center text-xs text-faint">Comparison reflects each product&apos;s primary positioning; competitor capabilities evolve — verify current specifics on their site.</p>
      </section>

      {/* Our differentiators */}
      <section className="mx-auto max-w-5xl px-5 pb-4">
        <div className="mx-auto mb-8 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Where we&apos;re different</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">What you get with us that you don&apos;t there.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {data.edges.map((e) => (
            <div key={e.t} className="card p-5">
              <div className="text-sm font-semibold text-ink">{e.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{e.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Honest choose-them / choose-us */}
      <section className="mx-auto max-w-4xl px-5 py-14">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-2xl border border-border bg-surface p-6">
            <div className="text-sm font-semibold text-ink">Choose {data.name} if…</div>
            <p className="mt-2 text-sm leading-relaxed text-muted">{data.chooseThem}</p>
          </div>
          <div className="rounded-2xl border border-accent/40 bg-accent-soft/40 p-6">
            <div className="text-sm font-semibold text-accent">Choose TensorShield if…</div>
            <p className="mt-2 text-sm leading-relaxed text-ink/80">{data.chooseUs}</p>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="mx-auto max-w-3xl px-5 pb-14">
        <h2 className="mb-8 text-center text-3xl font-semibold leading-tight tracking-tight">Frequently asked</h2>
        <div className="space-y-3">
          {data.faq.map(([q, a]) => (
            <div key={q} className="card p-5">
              <div className="flex items-start gap-2 text-sm font-semibold text-ink">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> {q}
              </div>
              <p className="mt-2 pl-6 text-sm leading-relaxed text-muted">{a}</p>
            </div>
          ))}
        </div>
        <FaqJsonLd items={data.faq} />
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-3xl px-5 pb-24 text-center">
        <div className="rounded-2xl border border-border bg-surface p-10">
          <h2 className="text-2xl font-semibold tracking-tight">See it on your own stack.</h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted">
            Start free and connect a system, or have our expert run the whole engagement. Either way you get real
            findings, a pentest, and audit-ready evidence — in one place.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/managed" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Have us run it
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
