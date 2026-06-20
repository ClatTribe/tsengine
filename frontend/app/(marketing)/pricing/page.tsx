import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";
import { Check, ArrowRight, Sparkles, Minus } from "lucide-react";

export const metadata = pageMeta({
  title: "Pricing — TensorShield",
  description: "Simple, transparent pricing for your fractional security team. Start free.",
  path: "/pricing",
});

const TIERS = [
  {
    name: "Free",
    price: "$0",
    cadence: "forever",
    blurb: "See your posture and your first fixes — no card required.",
    cta: "Start free",
    href: "/signup",
    highlight: false,
    features: [
      "Connect 1 system",
      "Continuous scanning + live dashboard",
      "Compliance posture (1 framework)",
      "Up to 3 fixes prepared / month",
      "Community support",
    ],
  },
  {
    name: "Growth",
    price: "$499",
    cadence: "/ month, billed annually",
    blurb: "The full fractional security team for a growing company.",
    cta: "Start free",
    href: "/signup",
    highlight: true,
    features: [
      "Unlimited systems (code · cloud · identity)",
      "All 14 frameworks — SOC 2 · ISO · GDPR · PCI · HIPAA · NIST · …",
      "Signed evidence packs + Trust Center",
      "Questionnaire automation",
      "Human-in-the-loop approvals + remediation",
      "Slack + PagerDuty + Jira/ServiceNow",
    ],
  },
  {
    name: "Scale",
    price: "Custom",
    cadence: "for larger teams",
    blurb: "Advanced controls, expert review, and the support to match.",
    cta: "Contact sales",
    href: "/demo",
    highlight: false,
    features: [
      "Everything in Growth",
      "SSO / SAML + role-based access",
      "On-demand human expert review",
      "Dedicated success engineer",
      "Custom integrations + SLAs",
      "Audit-firm-ready evidence exports",
    ],
  },
];

const FAQ = [
  ["Do I need a security engineer to use TensorShield?", "No — that's the point. TensorShield does the engineer's and the compliance manager's work, and only pulls you in to approve anything consequential. The whole experience is built for a non-technical founder or ops lead."],
  ["What does \"human in the loop\" actually mean?", "Low-risk fixes apply automatically. Anything consequential (a config change, an identity action) waits for one tap of your approval — and every decision, automated or human, is signed into a tamper-evident ledger."],
  ["Is the free plan really free?", "Yes. Connect a system, see your real posture and compliance gaps, and get your first fixes prepared — no credit card. Upgrade when you're ready for the full team."],
  ["How fast is setup?", "Minutes. Connect a system via OAuth and the agent discovers your assets and starts scanning immediately. No agents to install, no playbooks to write."],
  ["Can auditors trust the evidence?", "Every finding cites the tool that proves it, and every compliance pack is ed25519-signed and pinned to the exact state it was assessed against — reproducible proof, not screenshots."],
];

// ComparePlans — the at-a-glance feature matrix every buyer expects below the tier cards.
// Cell value: "yes" | "no" | a literal string. Mirrors the TIERS feature lists, no new claims.
const COMPARE: { section: string; rows: { label: string; cells: [string, string, string] }[] }[] = [
  {
    section: "Coverage",
    rows: [
      { label: "Connected systems", cells: ["1", "Unlimited", "Unlimited"] },
      { label: "Continuous scanning + live dashboard", cells: ["yes", "yes", "yes"] },
      { label: "Asset types (code · cloud · web · identity)", cells: ["All", "All", "All"] },
      { label: "OSS scanners wrapped", cells: ["30+", "30+", "30+"] },
    ],
  },
  {
    section: "Compliance",
    rows: [
      { label: "Frameworks mapped", cells: ["1", "All 14", "All 14"] },
      { label: "Signed evidence packs + Trust Center", cells: ["no", "yes", "yes"] },
      { label: "Questionnaire automation", cells: ["no", "yes", "yes"] },
      { label: "Audit-firm-ready exports", cells: ["no", "yes", "yes"] },
    ],
  },
  {
    section: "Autonomy & remediation",
    rows: [
      { label: "Fixes prepared / month", cells: ["3", "Unlimited", "Unlimited"] },
      { label: "Human-in-the-loop approvals", cells: ["no", "yes", "yes"] },
      { label: "Signed decision ledger", cells: ["yes", "yes", "yes"] },
      { label: "On-demand human expert review", cells: ["no", "no", "yes"] },
    ],
  },
  {
    section: "Platform",
    rows: [
      { label: "Integrations (Slack · Jira · PagerDuty)", cells: ["no", "yes", "yes"] },
      { label: "SSO / SAML + role-based access", cells: ["no", "no", "yes"] },
      { label: "Dedicated success engineer", cells: ["no", "no", "yes"] },
      { label: "Custom integrations + SLAs", cells: ["no", "no", "yes"] },
    ],
  },
];

function ComparePlans() {
  const tiers = ["Free", "Growth", "Scale"];
  return (
    <section className="mx-auto max-w-4xl px-5 pb-4 pt-14">
      <h2 className="text-center text-2xl font-semibold tracking-tight">Compare plans</h2>
      <div className="mt-8 overflow-x-auto">
        <table className="w-full min-w-[560px] border-separate border-spacing-0 text-sm">
          <thead>
            <tr>
              <th className="w-[40%] p-0" />
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
      </div>
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
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-6 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Sparkles className="h-3.5 w-3.5 text-accent" /> Start free · upgrade when you grow
          </span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-5xl">Pricing that grows with you</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            One fractional security team, one simple plan. No per-seat surprises, no security hire.
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 pb-8">
        <div className="grid gap-5 lg:grid-cols-3">
          {TIERS.map((t) => (
            <div
              key={t.name}
              className={
                t.highlight
                  ? "relative rounded-2xl border-2 border-accent bg-surface p-6 shadow-card-hover"
                  : "relative rounded-2xl border border-border bg-surface p-6 shadow-card"
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
        </div>
        <p className="mt-6 text-center text-xs text-faint">
          Prices in USD. Annual billing saves ~20% vs monthly. All plans include continuous monitoring and the signed ledger.
        </p>
      </section>

      {/* Compare plans */}
      <ComparePlans />

      {/* FAQ */}
      <section className="mx-auto max-w-3xl px-5 py-20">
        {/* schema.org FAQPage — same array as below, so the markup matches the visible Q&A. */}
        <FaqJsonLd items={FAQ} />
        <h2 className="text-center text-2xl font-semibold tracking-tight">Frequently asked</h2>
        <div className="mt-8 divide-y divide-border rounded-2xl border border-border bg-surface">
          {FAQ.map(([q, a]) => (
            <div key={q} className="p-5">
              <h3 className="text-sm font-semibold text-ink">{q}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{a}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Start with the free plan today.</h2>
          <p className="mx-auto mt-3 max-w-md text-white/75">See your posture and first fixes in minutes. Upgrade when you&apos;re ready.</p>
          <Link href="/signup" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
