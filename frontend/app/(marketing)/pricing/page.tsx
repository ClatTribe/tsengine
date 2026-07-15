import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import { Reveal } from "@/components/marketing/reveal";
import { Check, ArrowRight, Sparkles, Minus } from "lucide-react";

export const metadata = pageMeta({
  title: "Pricing — TensorShield",
  description:
    "Priced in ₹ for Indian teams, built for companies with no security hire. Free to see your real posture. ₹7,999/mo for your AI Security Engineer and AI Pentester across code, cloud and SaaS — a fraction of one pentest.",
  path: "/pricing",
});

// Three tiers for an SMB buyer, priced in ₹. The positioning, in CUSTOMER terms (never internal layer
// jargon): the TWO AI AGENTS ARE THE PRODUCT, and they start at Core — not Enterprise. Free is scanning
// only (it costs us no model spend, which is why it can stay free forever). Core runs both agents on the
// TENANT'S OWN key (resolveAgentLLM allows a tenant's own model on any plan — it costs the operator
// nothing), so the ₹ price stays flat and predictable and we never mark up a model bill. Enterprise is
// the same agents with the model run BY US (the only operator-funded tier, per plan.go AIEnabled).
const TIERS = [
  {
    name: "Free",
    price: "₹0",
    cadence: "forever",
    blurb: "See your real posture. 30+ scanners across code, cloud, attack surface and identity, with cross-surface correlation and a SOC 2 readiness view — on 2 targets. Scanning only: the AI agents start at Core. No card, free forever.",
    cta: "Start free",
    href: "/signup",
    highlight: false,
    persona: false,
    features: [
      "2 scan targets",
      "All 5 categories — code · cloud · attack surface · identity · compliance",
      "30+ scanners with cross-surface correlation + threat-intel",
      "Findings dashboard + SOC 2 readiness view",
      "Signed decision ledger",
      "Community support",
      "No AI agents — scanning only",
    ],
  },
  {
    name: "Core",
    price: "₹7,999",
    cadence: "/ month + GST",
    annual: "or ₹79,990/yr — ~2 months free",
    blurb: "Your AI Security Engineer and AI Pentester, working your whole estate — plus every scanner, all 22 frameworks, continuous monitoring and signed evidence. Connect your own LLM key and the agents turn on: you pay your model bill, we don't mark it up.",
    cta: "Start free",
    href: "/signup",
    highlight: true,
    persona: false,
    features: [
      "★ AI Security Engineer — triages the noise, proves what's real, writes the fix",
      "★ AI Pentester — actually exploits it to prove it, then reports it",
      "Bring your own LLM key — Anthropic, OpenAI-compatible, or a local model",
      "Up to 25 scan targets",
      "Every scanner + cross-surface correlation, threat-intel, attack paths",
      "Continuous monitoring + incidents",
      "All 22 frameworks — SOC 2 · ISO · GDPR · PCI · HIPAA · NIST · …",
      "Signed evidence packs + Trust Center",
      "You approve anything consequential — nothing ships without a human",
      "Self-serve, managed, or MSP delivery — your service model",
      "Slack · Jira · email alerts",
    ],
  },
  {
    name: "Enterprise",
    price: "Talk to us",
    cadence: "AI included — no key to manage",
    blurb: "Everything in Core, but we run the model for you — no LLM key, no model bill, no capacity planning. Unlimited scale, a named human accountable for the calls that matter, managed / MSP delivery and SSO.",
    cta: "Contact sales",
    href: "/demo",
    highlight: false,
    persona: true,
    features: [
      "★ Both AI agents — included, running on our models (no key to configure)",
      "A named security expert accountable for every consequential call",
      "Unlimited scan targets",
      "Managed service + MSP / partner desk",
      "SSO / SAML + role-based access",
      "Custom / bring-your-own frameworks",
      "Dedicated success engineer + SLAs · on-prem option",
    ],
  },
];

const FAQ = [
  ["Is the Free plan really free — for me and for you?", "Yes, both ways. Free runs only the open-source scanners across all five categories, so there is no AI cost on our side — which is exactly why we can keep it free forever. You connect up to 2 targets, see your real posture and SOC 2 readiness, with no credit card. The AI security engineer turns on when you upgrade."],
  ["What do I get on Core that Free doesn't have?", "The two AI agents — your AI Security Engineer and AI Pentester — plus every scanner with cross-surface correlation, continuous monitoring with incidents, all 22 compliance frameworks with signed evidence packs, questionnaire automation, and the approval loop that actually closes findings. ₹7,999/mo (or ₹79,990/yr), up to 25 targets. You connect your own LLM key and the agents turn on."],
  ["How are the tiers structured?", "Free to see your real posture with the scanners. Core is the whole product — both AI agents running on your own LLM key, all 22 frameworks, continuous monitoring, signed evidence — self-serve, managed, or via your MSP. Enterprise (talk to us) is the same agents but we run the model for you, with unlimited targets, SSO, a named accountable expert, and a managed/MSP partner desk."],
  ["Why do I bring my own LLM key on Core?", "Because it's cheaper and more honest. You pay your model provider directly — Anthropic, any OpenAI-compatible provider, or a local model — at cost, with no markup from us, and you keep control of where your data goes. It takes a minute in Settings. If you'd rather not think about models at all, Enterprise includes them and we handle it."],
  ["Which models can I connect?", "Anthropic, any OpenAI-compatible provider, or a self-hosted model (Ollama / vLLM) if you want everything to stay on your own infrastructure. You pick the model; the agents use it for triage, proving exploitability, and writing fixes."],
  ["Do I need a security engineer to use it?", "No — that's the point. TensorShield does the security engineer's and the compliance manager's work, and only pulls you in to approve anything consequential. Built for a non-technical founder or ops lead."],
  ["What does \"human in the loop\" mean?", "Low-risk fixes apply automatically. Anything consequential (a config change, an identity action) waits for one tap of your approval — and every decision, automated or human, is signed into a tamper-evident ledger."],
  ["What if I'd rather not run it at all?", "Have it fully managed. Our security expert — or your MSP / consultancy partner — operates TensorShield for you: they triage, approve, and sign off, and you get the outcome plus named accountability. Same engine and signed evidence, priced per engagement."],
  ["Can auditors trust the evidence?", "Every finding cites the tool that proves it, and every compliance pack is ed25519-signed and pinned to the exact state it was assessed against — reproducible proof, not screenshots."],
];

// ComparePlans — the at-a-glance matrix. Cell value: "yes" | "no" | a literal string. Mirrors
// the TIERS lists, no new claims. Order: Free · Core · Enterprise.
// The load-bearing line: the AI agents start at CORE, on the tenant's OWN model key ("your key"), and
// Enterprise is the same agents with the model funded by us ("included") — plan.go's AIEnabled gates
// only the OPERATOR-funded model, never a tenant's own.
const COMPARE: { section: string; rows: { label: string; cells: [string, string, string] }[] }[] = [
  {
    section: "What we scan",
    rows: [
      { label: "Scan targets", cells: ["2", "Up to 25", "Unlimited"] },
      { label: "Categories — code · cloud · attack · identity · compliance", cells: ["All 5", "All 5", "All 5"] },
      { label: "OSS scanners wrapped", cells: ["30+", "30+", "30+"] },
      { label: "Cross-surface correlation + attack paths + threat-intel", cells: ["yes", "yes", "yes"] },
      { label: "Continuous monitoring + incidents", cells: ["no", "yes", "yes"] },
    ],
  },
  {
    section: "Compliance & evidence",
    rows: [
      { label: "Frameworks mapped", cells: ["SOC 2 readiness", "All 22", "All 22 + custom"] },
      { label: "Signed evidence packs + Trust Center", cells: ["no", "yes", "yes"] },
      { label: "Questionnaire automation", cells: ["no", "yes", "yes"] },
      { label: "Human-in-the-loop approvals + apply", cells: ["no", "yes", "yes"] },
      { label: "Signed decision ledger", cells: ["yes", "yes", "yes"] },
    ],
  },
  {
    section: "The AI agents",
    rows: [
      { label: "AI Security Engineer — triage · prove · fix · explain", cells: ["no", "your key", "included"] },
      { label: "AI Pentester — proves it by exploiting it, then reports", cells: ["no", "your key", "included"] },
      { label: "Plain-English narrative & remediation", cells: ["no", "your key", "included"] },
      { label: "Who pays for the model", cells: ["—", "You (no markup)", "We do"] },
      { label: "Connect any model — Anthropic · OpenAI-compatible · local", cells: ["no", "yes", "managed for you"] },
    ],
  },
  {
    section: "Delivery & platform",
    rows: [
      { label: "Service model — self-serve · managed · MSP", cells: ["Self-serve", "Any", "Any"] },
      { label: "Integrations (Slack · Jira · email)", cells: ["no", "yes", "yes"] },
      { label: "SSO / SAML + role-based access", cells: ["no", "no", "yes"] },
      { label: "Support", cells: ["Community", "Standard", "Dedicated + SLA"] },
    ],
  },
];

function ComparePlans() {
  const tiers = ["Free", "Core", "Enterprise"];
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
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">A security team for less than one pentest.</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Priced in ₹, built for teams with no security hire. Start free to see your real posture. On{" "}
            <strong className="font-semibold text-ink">Core</strong>, your AI Security Engineer and AI Pentester work
            your code, cloud and SaaS every day — for less per year than a single pentest costs once. You run it, we run
            it, or your MSP does.
          </p>
          {/* The pricing spine in customer terms: scanning on every plan, the two AI
              agents from Core, and a named human accountable. Personas cross-link out. */}
          <div className="mx-auto mt-7 flex max-w-2xl flex-wrap items-center justify-center gap-2 text-xs">
            <span className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink">Scanning <span className="text-faint">· every plan</span></span>
            <span className="text-faint">+</span>
            <Link href="/ai-security-engineer" className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink transition hover:border-accent/50 hover:text-accent">AI Security Engineer <span className="text-faint">· Talk to us</span></Link>
            <span className="text-faint">+</span>
            <Link href="/ai-pentest" className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink transition hover:border-accent/50 hover:text-accent">AI Pentester <span className="text-faint">· Talk to us</span></Link>
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
              {t.persona && (
                <div className="mt-4 flex flex-wrap gap-x-4 gap-y-1 border-t border-border pt-4 text-xs font-medium">
                  <Link href="/ai-security-engineer" className="text-accent transition hover:underline">Meet the AI Security Engineer →</Link>
                  <Link href="/ai-pentest" className="text-accent transition hover:underline">Meet the AI Pentester →</Link>
                </div>
              )}
            </div>
          ))}
        </Reveal>
        <p className="mt-6 text-center text-xs text-faint">
          Prices in INR, exclusive of 18% GST. <span className="text-muted">Free is genuinely free — it runs only the
          open-source scanners (no AI cost on our side), so we never have to take it away.</span> Annual billing
          on Core saves ~2 months. The signed decision ledger is on every plan.
        </p>
      </section>

      {/* The three GTM models (§18.5) live canonically on /partners now. Pricing keeps a compact pointer:
          every paid tier is delivered self-serve OR managed / via an MSP — only who runs the HITL differs. */}
      <section className="mx-auto max-w-4xl px-5 pb-2 pt-12">
        <Reveal className="flex flex-col items-center gap-4 rounded-2xl border border-border bg-surface px-6 py-7 text-center sm:flex-row sm:justify-between sm:text-left">
          <div>
            <h2 className="text-lg font-semibold tracking-tight">Pick your service model</h2>
            <p className="mt-1 max-w-xl text-sm leading-relaxed text-muted">
              Any paid tier runs three ways — you run it, we run it (managed), or your MSP runs it for clients.
              The product is identical; only who makes the human-in-the-loop calls changes.
            </p>
          </div>
          <Link
            href="/partners"
            className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-semibold text-ink transition hover:border-accent/40 hover:text-accent"
          >
            Compare service models <ArrowRight className="h-4 w-4" />
          </Link>
        </Reveal>
      </section>

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
