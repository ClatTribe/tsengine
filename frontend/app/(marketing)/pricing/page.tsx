import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import { EngageModels } from "@/components/marketing/engage-models";
import { Reveal } from "@/components/marketing/reveal";
import { Check, ArrowRight, Sparkles, Minus } from "lucide-react";

export const metadata = pageMeta({
  title: "Pricing — TensorShield",
  description:
    "Simple, transparent pricing in ₹ for Indian teams. A genuinely-free tier, one paid plan with the full AI security + compliance engineer, and Enterprise for unlimited scale.",
  path: "/pricing",
});

// Three tiers, backed 1:1 by pkg/platform/plan.go Entitlements so the product never drifts
// from the page. The five categories (code · cloud · attack · identity · compliance) are on
// EVERY tier — Free shows real posture via the deterministic scanners; paid adds the AI engineer.
const TIERS = [
  {
    name: "Free",
    price: "₹0",
    cadence: "forever",
    blurb: "Your deterministic security + compliance posture — 30+ scanners, cross-surface correlation, threat-intel. The substrate, free forever (no AI/LLM cost to run). No card.",
    cta: "Start free",
    href: "/signup",
    highlight: false,
    features: [
      "2 scan targets",
      "All 5 categories — code · cloud · attack surface · identity · compliance",
      "30+ OSS scanners (deterministic, on-demand)",
      "Findings dashboard + SOC 2 readiness view",
      "Signed decision ledger",
      "Community support",
    ],
  },
  {
    name: "Growth",
    price: "₹7,999",
    cadence: "/ month + GST",
    annual: "or ₹79,990/yr — ~2 months free",
    blurb: "Everything in Free + your AI Security Engineer — reasons over your whole estate, prioritizes, chains, fixes, and explains in plain English.",
    cta: "Start free",
    href: "/signup",
    highlight: true,
    features: [
      "Up to 25 scan targets",
      "AI security engineer — prioritization, attack chains, AI fixes, plain-English",
      "Continuous monitoring + incidents",
      "All 22 frameworks — SOC 2 · ISO · GDPR · PCI · HIPAA · NIST · …",
      "Signed evidence packs + Trust Center",
      "Human-in-the-loop approvals + remediation",
      "Slack · Jira · email alerts",
    ],
  },
  {
    name: "Enterprise",
    price: "Talk to us",
    cadence: "unlimited",
    blurb: "Everything in Growth + your AI Pentester (exploitation-proven VAPT) — plus unlimited scale and managed / MSP delivery.",
    cta: "Contact sales",
    href: "/demo",
    highlight: false,
    features: [
      "Unlimited scan targets",
      "Autonomous AI pentest — exploitation-proven (XBOW-class)",
      "Managed service + MSP / partner desk",
      "SSO / SAML + role-based access",
      "Custom / bring-your-own frameworks",
      "Dedicated success engineer + SLAs",
      "On-prem / single-tenant option",
    ],
  },
];

const FAQ = [
  ["Is the Free plan really free — for me and for you?", "Yes, both ways. Free runs only the deterministic open-source scanners across all five categories, so there's no AI/LLM cost on our side — which is exactly why we can keep it free forever. You connect up to 2 targets, see your real posture and SOC 2 readiness, with no credit card. The AI security engineer turns on when you upgrade."],
  ["What do I get on Growth that Free doesn't have?", "The AI: an agent that prioritizes findings, traces attack chains across code, cloud and identity, writes fixes, and explains everything in plain English — plus continuous monitoring with incidents, all 22 compliance frameworks with signed evidence, and the human-in-the-loop apply loop that actually closes findings. ₹7,999/mo (or ₹79,990/yr), up to 25 targets."],
  ["Can I use the AI on the Free plan with my own model key?", "Yes — bring your own LLM key. Free doesn't include operator-funded AI (no LLM cost on our side is exactly what keeps it free to run), but connect your own model key in Settings → LLM — any OpenAI-compatible provider, or a local Ollama — and the AI Security Engineer runs on your plan, at your cost. Or upgrade to Growth and we run it for you."],
  ["Why only one paid tier?", "Because most teams don't want to decode a feature matrix. Free to try, Growth for the full product, and Enterprise (talk to us) when you need unlimited targets, autonomous pentest, SSO, or a managed/MSP delivery. Simple."],
  ["Do I need a security engineer to use it?", "No — that's the point. TensorShield does the security engineer's and the compliance manager's work, and only pulls you in to approve anything consequential. Built for a non-technical founder or ops lead."],
  ["What does \"human in the loop\" mean?", "Low-risk fixes apply automatically. Anything consequential (a config change, an identity action) waits for one tap of your approval — and every decision, automated or human, is signed into a tamper-evident ledger."],
  ["What if I'd rather not run it at all?", "Have it fully managed. Our security expert — or your MSP / consultancy partner — operates TensorShield for you: they triage, approve, and sign off, and you get the outcome plus named accountability. Same engine and signed evidence, priced per engagement."],
  ["Can auditors trust the evidence?", "Every finding cites the tool that proves it, and every compliance pack is ed25519-signed and pinned to the exact state it was assessed against — reproducible proof, not screenshots."],
];

// ComparePlans — the at-a-glance matrix. Cell value: "yes" | "no" | a literal string. Mirrors
// the TIERS lists + the backend Entitlements, no new claims. Order: Free · Growth · Enterprise.
const COMPARE: { section: string; rows: { label: string; cells: [string, string, string] }[] }[] = [
  {
    section: "Coverage",
    rows: [
      { label: "Scan targets", cells: ["2", "Up to 25", "Unlimited"] },
      { label: "Categories — code · cloud · attack · identity · compliance", cells: ["All 5", "All 5", "All 5"] },
      { label: "OSS scanners wrapped", cells: ["30+", "30+", "30+"] },
      { label: "Continuous monitoring + incidents", cells: ["no", "yes", "yes"] },
    ],
  },
  {
    section: "AI security engineer",
    rows: [
      { label: "AI prioritization, attack chains & fixes", cells: ["no", "yes", "yes"] },
      { label: "Plain-English explanations", cells: ["no", "yes", "yes"] },
      { label: "Human-in-the-loop approvals + apply", cells: ["no", "yes", "yes"] },
      { label: "Autonomous AI pentest (XBOW-class)", cells: ["no", "no", "yes"] },
    ],
  },
  {
    section: "Compliance",
    rows: [
      { label: "Frameworks mapped", cells: ["SOC 2 readiness", "All 22", "All 22 + custom"] },
      { label: "Signed evidence packs + Trust Center", cells: ["no", "yes", "yes"] },
      { label: "Questionnaire automation", cells: ["no", "yes", "yes"] },
      { label: "Signed decision ledger", cells: ["yes", "yes", "yes"] },
    ],
  },
  {
    section: "Platform",
    rows: [
      { label: "Integrations (Slack · Jira · email)", cells: ["no", "yes", "yes"] },
      { label: "SSO / SAML + role-based access", cells: ["no", "no", "yes"] },
      { label: "Managed service / MSP desk", cells: ["no", "no", "yes"] },
      { label: "Support", cells: ["Community", "Standard", "Dedicated + SLA"] },
    ],
  },
];

function ComparePlans() {
  const tiers = ["Free", "Growth", "Enterprise"];
  return (
    <section className="mx-auto max-w-4xl px-5 pb-4 pt-14">
      <h2 className="text-center text-2xl font-semibold tracking-tight">Compare plans</h2>
      <Reveal delay={60} className="mt-8 overflow-x-auto">
        <table className="w-full min-w-[640px] border-separate border-spacing-0 text-sm">
          <thead>
            <tr>
              <th className="w-[46%] p-0" />
              {tiers.map((t, i) => (
                <th
                  key={t}
                  className={`px-4 py-2.5 text-center text-sm font-semibold ${i === 1 ? "rounded-t-xl bg-accent-soft/60 text-accent ring-1 ring-accent/30" : "text-ink"}`}
                >
                  {t}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {COMPARE.map((grp) => (
              <FragmentGroup key={grp.section} grp={grp} />
            ))}
          </tbody>
        </table>
      </Reveal>
    </section>
  );
}

function FragmentGroup({ grp }: { grp: (typeof COMPARE)[number] }) {
  return (
    <>
      <tr>
        <td colSpan={4} className="border-t border-border pb-1 pt-5 text-[11px] font-semibold uppercase tracking-wider text-faint">
          {grp.section}
        </td>
      </tr>
      {grp.rows.map((r) => (
        <tr key={r.label}>
          <td className="border-t border-border py-2.5 pr-4 text-sm text-ink">{r.label}</td>
          {r.cells.map((v, ci) => (
            <td key={ci} className={`border-t border-border px-4 py-2.5 text-center ${ci === 1 ? "bg-accent-soft/25" : ""}`}>
              <PlanCell v={v} highlight={ci === 1} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

function PlanCell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <Check className={`mx-auto h-4 w-4 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <Minus className="mx-auto h-4 w-4 text-faint/50" />;
  return <span className={`text-xs font-medium ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}

export default function Pricing() {
  return (
    <>
      <section className="relative overflow-hidden">
        {/* animated aurora backdrop — consistent with the landing */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-24 left-1/2 h-[24rem] w-[34rem] -translate-x-1/2 rounded-full bg-accent/15 blur-[110px] animate-aurora" />
          <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(16,24,40,0.025)_1px,transparent_1px),linear-gradient(to_bottom,rgba(16,24,40,0.025)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]" />
        </div>
        <Reveal as="div" className="relative mx-auto max-w-3xl px-5 pb-6 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface/80 px-3 py-1 text-xs font-medium text-muted shadow-sm backdrop-blur">
            <Sparkles className="h-3.5 w-3.5 text-accent" /> Built for Indian teams · priced in ₹
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">Pricing that grows with you</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Genuinely free to start, one simple paid plan for the full AI security + compliance team, and
            Enterprise when you scale. No per-seat surprises, no security hire — a fraction of a single retainer.
          </p>
          {/* The architecture as the pricing spine: a free deterministic substrate, two AI teammates you
              add on top, and a named human accountable for the calls that matter. */}
          <div className="mx-auto mt-7 flex max-w-2xl flex-wrap items-center justify-center gap-2 text-xs">
            <span className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink">Deterministic posture <span className="text-faint">· Free</span></span>
            <span className="text-faint">+</span>
            <span className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink">AI Security Engineer <span className="text-faint">· Growth</span></span>
            <span className="text-faint">+</span>
            <span className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink">AI Pentester <span className="text-faint">· Enterprise</span></span>
            <span className="text-faint">+</span>
            <span className="rounded-md border border-dashed border-border px-2.5 py-1 font-medium text-muted">a named human (HITL)</span>
          </div>
        </Reveal>
      </section>

      <section className="mx-auto max-w-5xl px-5 pb-8">
        <Reveal delay={80} className="grid items-stretch gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {TIERS.map((t) => (
            <div
              key={t.name}
              className={
                t.highlight
                  ? "relative flex flex-col rounded-2xl border-2 border-accent bg-surface p-6 shadow-elevated transition hover:-translate-y-1 hover:shadow-card-hover"
                  : "relative flex flex-col rounded-2xl border border-border bg-surface p-6 shadow-card transition hover:-translate-y-1 hover:border-accent/40 hover:shadow-card-hover"
              }
            >
              {t.highlight && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-accent px-3 py-1 text-[11px] font-semibold text-white shadow-sm">
                  Most popular
                </span>
              )}
              <div className="text-sm font-semibold text-ink">{t.name}</div>
              <div className="mt-3 flex items-baseline gap-1.5">
                <span className="text-4xl font-semibold tracking-tight">{t.price}</span>
                <span className="text-sm text-muted">{t.cadence}</span>
              </div>
              <div className="mt-1 h-4 text-xs font-medium text-accent">{t.annual ?? ""}</div>
              <p className="mt-2 text-sm leading-relaxed text-muted">{t.blurb}</p>
              <Link
                href={t.href}
                className={
                  t.highlight
                    ? "mt-5 flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
                    : "mt-5 flex w-full items-center justify-center gap-2 rounded-xl border border-border bg-surface px-4 py-2.5 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong"
                }
              >
                {t.cta} <ArrowRight className="h-4 w-4" />
              </Link>
              <ul className="mt-6 space-y-2.5">
                {t.features.map((f) => (
                  <li key={f} className="flex items-start gap-2.5 text-sm text-ink">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {f}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </Reveal>
        <p className="mt-6 text-center text-xs text-faint">
          Prices in INR, exclusive of 18% GST. <span className="text-muted">Free is genuinely free — it runs only the
          deterministic OSS scanners (no AI/LLM cost on our side), so we never have to take it away.</span> Annual billing
          on Growth saves ~2 months. The signed decision ledger is on every plan.
        </p>
      </section>

      {/* The three GTM models as co-equal options (§18.5): self-serve, managed, MSP — the practitioner
          layer, first-class on the pricing page (was a single managed/MSP band). The only thing that
          differs is who employs the human-in-the-loop. */}
      <EngageModels />

      {/* Compare plans */}
      <ComparePlans />

      {/* FAQ */}
      <section className="mx-auto max-w-3xl px-5 py-20">
        {/* schema.org FAQPage — same array as below, so the markup matches the visible Q&A. */}
        <FaqJsonLd items={FAQ} />
        <h2 className="text-center text-2xl font-semibold tracking-tight">Frequently asked</h2>
        <Reveal delay={60} className="mt-8 divide-y divide-border rounded-2xl border border-border bg-surface">
          {FAQ.map(([q, a]) => (
            <div key={q} className="p-5">
              <h3 className="text-sm font-semibold text-ink">{q}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{a}</p>
            </div>
          ))}
        </Reveal>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Start with the free plan today.</h2>
          <p className="mx-auto mt-3 max-w-md text-white/75">See your posture and first findings in minutes. Upgrade when you&apos;re ready.</p>
          <Link href="/signup" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
