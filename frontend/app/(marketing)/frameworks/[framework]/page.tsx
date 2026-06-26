import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { ArrowRight, CheckCircle2, ShieldCheck, FileCheck2, Radar, Lock } from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_DESC, FRAMEWORK_CATEGORY } from "@/lib/frameworks";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";

// Frameworks that culminate in a formal third-party certificate / attestation report (an auditor issues it) —
// vs. regulations/frameworks that are an ongoing legal obligation, not a one-time certificate. Drives the
// honest phrasing of the "does TensorShield certify me?" FAQ answer (§10 — never claim to issue an attestation).
const ATTESTED = new Set(["soc2", "iso27001", "iso27701", "iso42001", "iso27018", "iso22301", "pci", "fedramp", "cmmc"]);

// frameworkFaq builds a unique, framework-specific Q&A set (so each of the 22 pages gets its own FAQ +
// FAQPage structured data, not thin-duplicate). Templated on the label/desc, branched on whether the framework
// is auditor-attested, and consistent with our honest line: we make you ready; an independent assessor attests;
// technical controls automate, policies/attestation need a named human.
function frameworkFaq(framework: string, label: string, desc: string): [string, string][] {
  const attested = ATTESTED.has(framework);
  const certLine = attested
    ? `No vendor can — and neither can we. A ${label} report is issued by an independent, licensed assessor; that's a legal requirement. What we do is get you audit-ready (automate the technical controls, map every finding to its ${label} control, and produce signed evidence) and quarterback the assessor through the engagement. On a managed plan, our named expert runs that prep for you.`
    : `${label} isn't a one-time certificate — it's an ongoing obligation. We continuously map your real posture to ${label}, flag gaps the moment they appear, prepare fixes, and keep a signed, current evidence trail — so you can demonstrate compliance whenever a customer, regulator, or auditor asks.`;
  return [
    [`What is ${label} and who needs it?`, `${desc} If your customers, buyers, or regulators ask about ${label}, or it's blocking an enterprise deal, it applies to you — and TensorShield gets you ready without a dedicated security hire.`],
    [`Does TensorShield make my company ${label}-compliant?`, certLine],
    [`What does TensorShield automate for ${label}, and what still needs a human?`, `The technical controls automate: continuous scanning across your code, cloud, identity, and apps, each finding mapped to the ${label} control it affects, with fixes prepared for one-tap approval. The human-only parts — writing policies, risk decisions, and the independent attestation — are where your team, our managed expert, or your MSP's expert signs off. We're explicit about that line; we never mark a control met from a scan alone.`],
    [`How long does it take to get ${label}-ready?`, `Most of the delay in a ${label} program is the manual technical work and evidence-gathering — exactly what we automate from day one. You'll see your ${label} posture in minutes and close the automatable gaps fast; the human controls (policies, training${attested ? ", and the assessor's timeline" : ""}) set the remainder of the schedule.`],
    [`How much does ${label} cost with TensorShield?`, `Far less than a consultant-led ${label} project or a full-time security hire. You can start free and see your ${label} posture before paying anything; the managed "we run it for you" option is priced on your stack and scope — book a call to scope it.`],
  ];
}

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
  "AI governance": "the AI-risk and model-security controls enterprise buyers and regulators now require",
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
  const faq = frameworkFaq(framework, i.label, i.desc);

  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
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
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent"><FeatureIcon name={Icon.displayName} className="h-4 w-4" /></span>
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

      {/* FAQ — framework-specific, with FAQPage structured data for rich results */}
      <section className="mx-auto max-w-3xl px-5 py-16">
        <h2 className="mb-8 text-center text-2xl font-semibold tracking-tight">{i.label} FAQ</h2>
        <div className="space-y-3">
          {faq.map(([q, a]) => (
            <div key={q} className="card p-5">
              <div className="flex items-start gap-2 text-sm font-semibold text-ink">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> {q}
              </div>
              <p className="mt-2 pl-6 text-sm leading-relaxed text-muted">{a}</p>
            </div>
          ))}
        </div>
        <FaqJsonLd items={faq} />
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
