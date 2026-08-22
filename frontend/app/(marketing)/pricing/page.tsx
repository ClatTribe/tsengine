import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import { Reveal } from "@/components/marketing/reveal";
import { Check, ArrowRight, Sparkles, Minus } from "lucide-react";
import { FRAMEWORK_COUNT } from "@/lib/frameworks";

export const metadata = pageMeta({
  title: "Pricing — TensorShield",
  description:
    "Simple, transparent pricing in ₹ for Indian teams. Free to see your real posture with the scanning engine — and bring your own LLM key to run both AI agents at your model cost. Core adds your AI Security Engineer; Core + Pentest adds your AI Pentester, for when a security review is blocking a deal. Enterprise is for scale and delivery: unlimited targets, SSO, managed/MSP.",
  path: "/pricing",
});

// Backed 1:1 by pkg/platform/plan.go Entitlements so the product never drifts from the page.
//
// The comment here used to say the two AI agents were "the Enterprise premium". That was never true of
// the code and had drifted badly: plan.go gates the AI Pentester on the "+pentest" ADD-ON, which by its
// own comment "unlocks AutonomousPentest on any base tier", and aimode.go resolves availability as
// `lim.AutonomousPentest || ownKey` — so a bring-your-own-key customer gets BOTH agents on ANY tier,
// Free included. The page was showing a three-rung ladder with the Pentester stranded on rung three
// while the product had already made it reachable from rung zero.
//
// That mattered commercially, not just for accuracy. For the Series A buyer the trigger is almost always
// "an enterprise customer's security review is blocking a deal", and the artifact that unblocks it is the
// pentest report — an ACUTE need, with an existing budget line and a date on it. The AI Security Engineer
// is the CHRONIC need: real, valuable, and deferrable. Stranding the acute product on the most expensive
// rung inverted the funnel. The copy below now matches both the code and the motion: the Pentester is
// reachable at your-own-API-key cost on Free, and as an add-on to Core.
const TIERS = [
  {
    name: "Free",
    price: "₹0",
    cadence: "forever",
    blurb: "A taste of the scanning engine — 30+ scanners, cross-surface correlation, threat-intel, SOC 2 readiness. Free forever (no AI/LLM cost to run). No card.",
    cta: "Start free",
    href: "/signup",
    highlight: false,
    persona: false,
    features: [
      // The bring-your-own-key route was position 7 of 8 on this card — read only by someone who had
      // already scanned the list, concluded "no AI on Free", and moved on. It is in fact the strongest
      // line on the page: paste an API key and BOTH agents run, including the Pentester, with no sales
      // call and no upgrade. Verified in code, not marketing licence — aimode.go resolves availability
      // as `lim.AutonomousPentest || ownKey`, so ownKey unlocks the Pentester on ANY tier, and
      // byok_free_test.go pins that it genuinely works on Free. Naming the Pentester explicitly matters
      // because that is the product a blocked deal actually needs, and burying it cost us the buyer
      // whose review is due next week.
      "Bring your own LLM key → both AI agents (Security Engineer + Pentester), at your model cost",
      "2 scan targets",
      "All 5 categories — code · cloud · attack surface · identity · compliance",
      "30+ OSS scanners (on-demand)",
      `Findings dashboard + all ${FRAMEWORK_COUNT} frameworks mapped`,
      "Human-in-the-loop approvals — you approve every fix",
      "Signed decision ledger",
      "Community support",
    ],
  },
  {
    name: "Core",
    price: "₹24,999",
    cadence: "/ month + GST",
    annual: "or ₹2,49,990/yr — ~2 months free",
    blurb: "Your AI Security Engineer, on top of the full scanning engine. It triages what actually matters, explains each issue in plain English, and proposes the fix for you to approve — it never changes anything on its own.",
    // Core is a PAID tier and there is no self-serve checkout, so it must not reuse the Free
    // tier's "Start free → /signup" CTA — that dead-ends a buyer on a free account whose only
    // upgrade signal is a 402. Fulfilment is contact-sales (an operator sets the plan once
    // payment is arranged), so send them where that actually happens.
    cta: "Talk to us to start",
    href: "/demo?plan=core",
    // Highlight moved to Core + Pentest — see the note there. Core remains the right tier for a team
    // whose deal is not currently blocked, which is the calmer, later conversation.
    highlight: false,
    persona: false,
    features: [
      "★ AI Security Engineer — triages, explains in plain English, proposes fixes you approve",
      "Up to 25 scan targets",
      "Full full detection — correlation, threat-intel, attack paths",
      "Continuous monitoring + incidents",
      `All ${FRAMEWORK_COUNT} frameworks — SOC 2 · ISO · GDPR · PCI · HIPAA · NIST · …`,
      "Signed evidence packs + Trust Center",
      "Human-in-the-loop approvals + remediation",
      "Self-serve, managed, or MSP delivery — your service model",
      "Slack · Jira · email alerts",
    ],
  },
  {
    // Named "Core + Pentest" rather than "Growth" because that is literally the plan string the code
    // models ("core+pentest" — plan.go knownAddOns), and because "Growth" told the buyer nothing about
    // what it does. It is highlighted rather than Core: for this buyer the entry point is the security
    // review that is blocking a deal today, not the continuous programme they will want next quarter.
    name: "Core + Pentest",
    price: "₹64,999",
    cadence: "/ month + GST",
    annual: "or ₹6,49,990/yr — ~2 months free",
    blurb: "For when a customer's security review is holding up a deal. Your AI Pentester proves which issues are actually exploitable — with the request to replay — and re-tests after the fix to show the hole is really closed. One artifact instead of three purchases: the report, the evidence, and the proof it got fixed.",
    cta: "Talk to us to start",
    href: "/demo?plan=growth",
    highlight: true,
    persona: true,
    features: [
      "Everything in Core, plus:",
      "★ AI Pentester — exploitation-proven, not just flagged",
      "VAPT report with a named human sign-off — what the reviewer is checking for",
      "Re-tests after every fix — proof the hole is closed",
      "Continuous testing, not once a year",
    ],
  },
  {
    name: "Enterprise",
    price: "Talk to us",
    cadence: "scale + delivery",
    blurb: "For when the constraint is scale or delivery rather than capability: unlimited targets, SSO, a managed or MSP partner desk, and a named human accountable for the calls that matter.",
    cta: "Contact sales",
    href: "/demo",
    highlight: false,
    persona: false,
    features: [
      "Everything in Core + Pentest, plus:",
      "Unlimited scan targets",
      "Managed service + MSP / partner desk",
      "SSO / SAML + role-based access",
      "Custom / bring-your-own frameworks",
      "Dedicated success engineer + SLAs · on-prem option",
    ],
  },
];

const FAQ = [
  ["Is the Free plan really free — for me and for you?", "Yes, both ways. Free runs only the open-source scanners across all five categories, so there's no AI/LLM cost on our side — which is exactly why we can keep it free forever. You connect up to 2 targets, see your real posture and SOC 2 readiness, with no credit card. The AI security engineer turns on when you upgrade."],
  ["What do I get on Core that Free doesn't have?", `Your AI Security Engineer — it triages what actually matters, explains each issue in plain English, and proposes the fix for you to approve. Plus the full scanning engine: every scanner with cross-surface correlation, continuous monitoring with incidents, all ${FRAMEWORK_COUNT} frameworks with signed evidence packs, and the human-in-the-loop apply loop that actually closes findings. ₹24,999/mo (or ₹2,49,990/yr), up to 25 targets.`],
  ["How are the tiers structured?", "Free to see your real posture with the scanning engine — and if you paste in your own LLM key, both AI agents run on Free at your model cost, no upgrade and no sales call. Core adds your AI Security Engineer (defense) on our side. Core + Pentest adds your AI Pentester (attack) — the one that proves which findings are actually exploitable, re-tests after each fix, and produces the VAPT report a customer's security review asks for. Enterprise is for when the constraint is scale or delivery rather than capability: unlimited targets, SSO, managed/MSP."],
  ["Can I run the AI on my own LLM key?", "Yes, on any plan including Free. Connect your own key in Settings → AI engine — any OpenAI-compatible provider, or a local Ollama — and the agents run at your model cost instead of ours. Useful if you already have credits, or if your policy is that your code only goes to a model you control."],
  ["Are there API rate limits?", "Yes — generous per-plan fair-use limits on the API, so one customer's automation can never slow the platform down for everyone else. Normal interactive use and CI never come close; paid plans get more headroom, and Enterprise is unmetered. If you hit a limit you get a clear 429 with a retry hint, never a hard lockout. AI spend is capped separately by the monthly budget you set."],
  ["Do I need a security engineer to use it?", "No — that's the point. TensorShield does the security engineer's and the compliance manager's work, and only pulls you in to approve anything consequential. Built for a non-technical founder or ops lead."],
  ["What does \"human in the loop\" mean?", "Low-risk fixes apply automatically. Anything consequential (a config change, an identity action) waits for one tap of your approval — and every decision, automated or human, is signed into a tamper-evident ledger."],
  ["What if I'd rather not run it at all?", "Have it fully managed. Our security expert — or your MSP / consultancy partner — operates TensorShield for you: they triage, approve, and sign off, and you get the outcome plus named accountability. Same engine and signed evidence, priced per engagement."],
  ["Can auditors trust the evidence?", "Every finding cites the tool that proves it, and every compliance pack is cryptographically signed and pinned to the exact state it was assessed against — reproducible proof, not screenshots."],
];

// ComparePlans — the at-a-glance matrix. Cell value: "yes" | "no" | a literal string. Mirrors
// the TIERS lists + the backend Entitlements, no new claims. Order: Free · Core · Core + Pentest · Enterprise.
// The load-bearing line: the AI agents are SELF-SERVE, not Enterprise-only. Core carries the AI Security
// Engineer (plan.go: PlanGrowth, labelled "Core", has AIEnabled) and Core + Pentest adds the AI Pentester
// via the "+pentest" add-on — the same add-on token the code already models, which is also why the tier
// is named for it now. Enterprise is scale and delivery — unlimited targets, SSO, managed/MSP — not a
// capability gate. This comment said the opposite long after the code changed, which is how a stale
// claim ends up in the page description search engines show.
const COMPARE: { section: string; rows: { label: string; cells: [string, string, string, string] }[] }[] = [
  {
    section: "Deterministic + ML-based scanning",
    rows: [
      { label: "Scan targets", cells: ["2", "Up to 25", "Up to 25", "Unlimited"] },
      { label: "Categories — code · cloud · attack · identity · compliance", cells: ["All 5", "All 5", "All 5", "All 5"] },
      { label: "OSS scanners wrapped", cells: ["30+", "30+", "30+", "30+"] },
      { label: "Cross-surface correlation + attack paths + threat-intel", cells: ["yes", "yes", "yes", "yes"] },
      { label: "Continuous monitoring + incidents", cells: ["no", "yes", "yes", "yes"] },
    ],
  },
  {
    section: "Compliance & evidence",
    rows: [
      { label: "Frameworks mapped", cells: [`All ${FRAMEWORK_COUNT}`, `All ${FRAMEWORK_COUNT}`, `All ${FRAMEWORK_COUNT}`, `All ${FRAMEWORK_COUNT} + custom`] },
      { label: "Signed evidence packs + Trust Center", cells: ["no", "yes", "yes", "yes"] },
      { label: "Questionnaire automation", cells: ["no", "yes", "yes", "yes"] },
      { label: "Human-in-the-loop approvals + apply", cells: ["yes", "yes", "yes", "yes"] },
      { label: "Signed decision ledger", cells: ["yes", "yes", "yes", "yes"] },
    ],
  },
  {
    section: "AI agents — self-serve, no sales call",
    rows: [
      { label: "AI Security Engineer — prioritize · chain · fix · explain", cells: ["no", "yes", "yes", "yes"] },
      { label: "AI Pentester — exploitation-proven VAPT", cells: ["no", "no", "yes", "yes"] },
      { label: "Plain-English findings — what broke, why it matters, what to do", cells: ["yes", "yes", "yes", "yes"] },
      { label: "Or: bring your own LLM key — AI on any plan, at your cost", cells: ["yes", "yes", "yes", "yes"] },
    ],
  },
  {
    section: "Delivery & platform",
    rows: [
      { label: "Service model — self-serve · managed · MSP", cells: ["Self-serve", "Any", "Any", "Any"] },
      { label: "Integrations (Slack · Jira · email)", cells: ["no", "yes", "yes", "yes"] },
      { label: "SSO / SAML + role-based access", cells: ["no", "no", "no", "yes"] },
      { label: "Support", cells: ["Community", "Standard", "Standard", "Dedicated + SLA"] },
    ],
  },
];

function ComparePlans() {
  const tiers = ["Free", "Core", "Core + Pentest", "Enterprise"];
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
        <Reveal as="div" className="relative mx-auto max-w-3xl px-5 pb-4 pt-14 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface/80 px-3 py-1 text-xs font-medium text-muted shadow-sm backdrop-blur">
            <Sparkles className="h-3.5 w-3.5 text-accent" /> Built for Indian teams · priced in ₹
          </span>
          {/* This H1 used to read "The scanning is the product. The AI agents are the premium." and the
              paragraph under it sent buyers to "Enterprise (talk to us) for the two AI agents". Both were
              false against the code — plan.go's "+pentest" add-on unlocks the Pentester on ANY base tier,
              and aimode.go resolves availability as `lim.AutonomousPentest || ownKey`, so a customer with
              their own API key runs BOTH agents on Free. The page was therefore telling its highest-intent
              visitor that the thing they came for needs a sales call. */}
          {/* Someone who clicked "Pricing" asked exactly one question, and the answer used to be
              below the fold: this hero was a positioning line ("The AI agents aren't the premium.
              They're the product.") followed by 60 words explaining tier architecture, with the
              first number ~700px further down. The headline now carries a price, the paragraph is
              one line, and the tier cards start near the fold. */}
          <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Start free. Add the AI engineer for ₹24,999&nbsp;/&nbsp;month.
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            The scanning engine is free forever. Bring your own AI key and both agents run on it at
            your cost, with no upgrade — or let us run them.
          </p>
          {/* The pricing spine in customer terms: deterministic + ML-based scanning on every tier, both AI
              agents reachable from Free via your own key, and a named human accountable. Personas cross-link out. */}
          <div className="mx-auto mt-5 flex max-w-2xl flex-wrap items-center justify-center gap-2 text-xs">
            <span className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink">Scanning engine <span className="text-faint">· free, every tier</span></span>
            <span className="text-faint">+</span>
            <Link href="/ai-security-engineer" className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink transition hover:border-accent/50 hover:text-accent">AI Security Engineer <span className="text-faint">· Core, or your key on Free</span></Link>
            <span className="text-faint">+</span>
            <Link href="/ai-pentest" className="rounded-md border border-border bg-surface px-2.5 py-1 font-medium text-ink transition hover:border-accent/50 hover:text-accent">AI Pentester <span className="text-faint">· + Pentest, or your key on Free</span></Link>
            <span className="text-faint">+</span>
            <span className="rounded-md border border-dashed border-border px-2.5 py-1 font-medium text-muted">a named human who signs</span>
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
              {/* Was "Most popular". Moving the highlight to Core + Pentest would have moved that claim
                  with it — and we have no sales data that makes it true of either tier. On a page whose
                  whole job this pass was removing claims the code doesn't support, shipping an unevidenced
                  one would be the same mistake in a nicer font. "If a review is blocking a deal" says why
                  it is highlighted, is verifiable, and is more useful to the buyer than a popularity claim. */}
              {t.highlight && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-accent px-3 py-1 text-[11px] font-semibold text-white shadow-sm">
                  If a review is blocking a deal
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
