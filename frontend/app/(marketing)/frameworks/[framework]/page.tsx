import Link from "next/link";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { ArrowRight, CheckCircle2, ShieldCheck, FileCheck2, Radar, Lock } from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_DESC, FRAMEWORK_CATEGORY } from "@/lib/frameworks";
import { pageMeta } from "@/lib/seo";

// Programmatic SEO: one landing page per supported framework, statically generated. The URL
// (/frameworks/soc2 …) and per-framework <title>/description target the high-intent
// "<framework> compliance software/automation for startups" queries the category leaders rank
// on. Content is templated but framework-specific (label, description, category angle) so each
// page is unique, not thin-duplicate.

export const dynamicParams = false; // only the 14 known frameworks; anything else → 404

export function generateStaticParams() {
  return FRAMEWORKS.map((framework) => ({ framework }));
}

// Category-specific angle so privacy / government / payments / trust pages read differently.
const CATEGORY_ANGLE: Record<string, string> = {
  "Security & trust": "the security & trust controls your customers' procurement teams check for",
  "Sector & payments": "the sector controls auditors and acquirers hold you to",
  Privacy: "the data-protection obligations regulators and customers expect",
  Government: "the federal-grade controls public-sector and enterprise buyers require",
};

function info(framework: string) {
  if (!FRAMEWORKS.includes(framework as (typeof FRAMEWORKS)[number])) return null;
  const label = FRAMEWORK_LABEL[framework] ?? framework;
  const desc = FRAMEWORK_DESC[framework] ?? "";
  const category = FRAMEWORK_CATEGORY[framework] ?? "Security & trust";
  return { label, desc, category, angle: CATEGORY_ANGLE[category] ?? CATEGORY_ANGLE["Security & trust"] };
}

export async function generateMetadata({ params }: { params: Promise<{ framework: string }> }): Promise<Metadata> {
  const { framework } = await params;
  const i = info(framework);
  if (!i) return {};
  const title = `${i.label} Compliance Automation for SMBs — TensorShield`;
  const description = `Get ${i.label}-ready without a security hire. TensorShield continuously maps your findings to ${i.label} controls, prepares fixes, and produces signed, auditor-ready evidence. ${i.desc}`;
  return pageMeta({ title, description, path: `/frameworks/${framework}` });
}

export default async function FrameworkLanding({ params }: { params: Promise<{ framework: string }> }) {
  const { framework } = await params;
  const i = info(framework);
  if (!i) notFound();

  const others = FRAMEWORKS.filter((f) => f !== framework);

  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <ShieldCheck className="h-3.5 w-3.5 text-accent" /> {i.category}
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            {i.label} compliance, <span className="text-accent">automated.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            {i.desc} TensorShield gets you {i.label}-ready without a security hire — covering {i.angle}.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See how it works
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">Continuous monitoring · signed evidence · no credit card to start</p>
        </div>
      </section>

      {/* How TensorShield gets you ready */}
      <section className="mx-auto max-w-5xl px-5 pb-8">
        <h2 className="mb-8 text-center text-2xl font-semibold tracking-tight">How TensorShield gets you {i.label}-ready</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { icon: Radar, t: "Continuous monitoring", d: `We watch your code, cloud, and identity 24/7 and surface what affects ${i.label} the moment it changes.` },
            { icon: FileCheck2, t: "Findings → controls", d: `Every finding maps to the ${i.label} control it touches — automatically, no spreadsheet.` },
            { icon: CheckCircle2, t: "Fixes prepared", d: "The agent prepares the remediation; you approve anything consequential in one tap." },
            { icon: Lock, t: "Signed evidence", d: `Get an ${i.label}-ready, ed25519-signed evidence pack an auditor can verify — not screenshots.` },
          ].map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent"><Icon className="h-4 w-4" /></span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Grounded claim */}
      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-16 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">A {i.label} control is a &ldquo;gap&rdquo; only because a real finding proves it.</h2>
          <p className="mx-auto mt-3 max-w-xl text-base leading-relaxed text-muted">
            No checkbox theater. Every {i.label} gap TensorShield reports is backed by a real, tool-verified finding,
            and every piece of evidence is signed and reproducible — so your posture survives an auditor&apos;s scrutiny.
          </p>
          <Link href="/security" className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
            How we keep evidence honest <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>

      {/* Internal-linking hub: other frameworks (SEO + discovery) */}
      <section className="mx-auto max-w-5xl px-5 py-16">
        <h2 className="mb-6 text-center text-sm font-semibold uppercase tracking-wider text-faint">TensorShield also automates</h2>
        <div className="flex flex-wrap items-center justify-center gap-2.5">
          {others.map((f) => (
            <Link key={f} href={`/frameworks/${f}`} className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3.5 py-1.5 text-sm font-medium text-ink transition hover:border-accent/40 hover:text-accent">
              {FRAMEWORK_LABEL[f] ?? f}
            </Link>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Start your path to {i.label} today.</h2>
          <p className="mx-auto mt-3 max-w-md text-white/75">Connect one system free and see your {i.label} posture in minutes.</p>
          <Link href="/signup" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
