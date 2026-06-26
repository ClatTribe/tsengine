import Link from "next/link";
import { ArrowRight, Cloud, Network, Layers, ShieldCheck, Globe, GitBranch, CheckCircle2, User, Users, Building2 } from "lucide-react";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import type { AssetPage } from "@/lib/asset-marketing";

const ICONS: Record<string, typeof Cloud> = {
  cloud: Cloud, network: Network, layers: Layers, shield: ShieldCheck, globe: Globe, git: GitBranch,
};

// AssetMarketingPage renders a per-asset SEO landing page from a single AssetPage entry — hero, what-it-
// assesses, how-it-works, the OSS tools + framework mapping, an FAQ (with FAQPage JSON-LD), the two-GTM
// engagement footer, and a CTA. All copy is grounded in the real anchor tools; no in-house-detector claims.
export function AssetMarketingPage({ data }: { data: AssetPage }) {
  const Icon = ICONS[data.icon] ?? ShieldCheck;
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Icon className="h-3.5 w-3.5 text-accent" /> {data.eyebrow}
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">{data.h1}</h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">{data.sub}</p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              {data.ctaPrimary} <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Talk to an expert
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">Wraps best-in-class OSS · grounded, low false positives · fixes are human-approved</p>
        </div>
      </section>

      {/* What we assess */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What we assess</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Coverage that maps to real risk.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {data.checks.map((c) => (
            <div key={c.t} className="card p-5">
              <div className="text-sm font-semibold text-ink">{c.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{c.d}</p>
            </div>
          ))}
        </div>
        <p className="mt-6 text-center text-xs text-faint">
          Powered by {data.tools.join(", ")} — best-in-class OSS, wrapped (never re-built in-house), so coverage
          equals the standalone tool.
        </p>
      </section>

      {/* How it works */}
      <section className="mx-auto max-w-5xl px-5 py-14">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">From target to fix, grounded at every step.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {data.how.map((s, i) => (
            <div key={s.t} className="card p-5">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent-soft text-sm font-semibold text-accent">{i + 1}</div>
              <div className="mt-3 text-sm font-semibold text-ink">{s.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{s.d}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 rounded-xl border border-border bg-surface p-5 text-sm leading-relaxed text-muted">
          <span className="font-medium text-ink">Compliance mapping.</span> {data.frameworks}
        </div>
      </section>

      {/* Two-GTM engagement — who runs it */}
      <section className="mx-auto max-w-5xl px-5 pb-4">
        <div className="mx-auto mb-8 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Three ways to run it</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">The product, or the product + an expert.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            The hard calls — the judgment, the legal attestation, the named accountability — are a human&apos;s. The
            only question is whose.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            { icon: User, t: "Self-serve", d: "Your team runs the product and owns the human-in-the-loop decisions.", href: "/signup", cta: "Start free" },
            { icon: Users, t: "Managed (we run it)", d: "We hire the expert — a vCISO / pentester / auditor liaison — who runs it on your behalf, named and accountable.", href: "/demo", cta: "Talk to us" },
            { icon: Building2, t: "MSP / channel", d: "You're an MSP or consultancy — run our product for your clients; your expert is the human-in-the-loop.", href: "/partners", cta: "Partner with us" },
          ].map((m) => (
            <Link key={m.t} href={m.href} className="card group p-5 transition hover:border-accent/50">
              <m.icon className="h-5 w-5 text-accent" />
              <div className="mt-3 text-sm font-semibold text-ink">{m.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{m.d}</p>
              <div className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent">{m.cta} <ArrowRight className="h-3.5 w-3.5" /></div>
            </Link>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section className="mx-auto max-w-3xl px-5 py-14">
        <h2 className="mb-8 text-center text-3xl font-semibold leading-tight tracking-tight">Frequently asked</h2>
        <div className="space-y-3">
          {data.faq.map((f) => (
            <div key={f.q} className="card p-5">
              <div className="flex items-start gap-2 text-sm font-semibold text-ink">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> {f.q}
              </div>
              <p className="mt-2 pl-6 text-sm leading-relaxed text-muted">{f.a}</p>
            </div>
          ))}
        </div>
        <FaqJsonLd items={data.faq.map((f) => [f.q, f.a] as const)} />
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-3xl px-5 pb-24 text-center">
        <div className="rounded-2xl border border-border bg-surface p-10">
          <h2 className="text-2xl font-semibold tracking-tight">{data.ctaPrimary} in minutes.</h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted">
            Start free, or have our expert run the whole engagement for you. Either way, you get a grounded,
            audit-ready result — not a noisy report you have to triage.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover">
              {data.ctaPrimary} <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Free instant check
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
