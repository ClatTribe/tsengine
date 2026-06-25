import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  Scale, ArrowRight, Clock, Wallet, RefreshCw, UserCheck, FileCheck2, Bot,
  CheckCircle2, XCircle, Minus,
} from "lucide-react";

export const metadata = pageMeta({
  title: "vs. a security & compliance consultant — continuous, not a retainer | TensorShield",
  description:
    "A security consultant retainer is expensive, slow, and point-in-time. TensorShield automates the repeatable 80% — scanning, fixes, evidence, monitoring, questionnaires — and keeps a named human for the judgment calls (risk acceptance, audit attestation, pentest sign-off). The outcome of a consultant, continuously, at a fraction of the cost.",
  path: "/vs-consulting",
});

// What the consultant retainer actually goes toward — and which half is repeatable labor vs human judgment.
const SPLIT = [
  {
    icon: Bot,
    head: "The repeatable 80% — automated",
    items: [
      "Scanning code, cloud, and identity for issues",
      "Writing and shipping the remediation",
      "Collecting and signing audit evidence",
      "Answering the security questionnaire",
      "Watching for new risk 24/7",
    ],
  },
  {
    icon: UserCheck,
    head: "The judgment 20% — a named human",
    items: [
      "Accepting or transferring residual risk (vCISO)",
      "Attesting each control to an auditor's standard",
      "Putting a name on the pentest report",
      "Publishing the security policies",
    ],
  },
];

// Traditional consultant vs TensorShield — the category wedge, in outcomes not tech.
const COMPARE: { label: string; consultant: string; us: string }[] = [
  { label: "Coverage", consultant: "point-in-time snapshot", us: "continuous, always-current" },
  { label: "Turnaround", consultant: "weeks per engagement", us: "minutes, then ongoing" },
  { label: "Cost for an SMB", consultant: "$5–20k/mo retainer", us: "a fraction of that" },
  { label: "Evidence", consultant: "a PDF that goes stale", us: "signed, reproducible, live" },
  { label: "Fixes", consultant: "a list you implement", us: "shipped on your approval" },
  { label: "The human judgment", consultant: "the consultant", us: "a named expert — ours or yours" },
];

export default function VsConsulting() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Scale className="h-3.5 w-3.5 text-accent" /> The consultant outcome, continuously
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            A security consultant&apos;s outcome — <span className="text-accent">without the retainer.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Most of what a security &amp; compliance consultant does is repeatable work a machine can do better and
            continuously. TensorShield automates that part — and keeps a named expert for the calls that genuinely
            need a human.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Talk to an expert
            </Link>
          </div>
        </div>
      </section>

      {/* The pain of the retainer */}
      <section className="mx-auto max-w-6xl px-5 py-16">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The problem</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">The retainer is slow, pricey, and goes stale.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            { icon: Wallet, t: "It costs a salary", d: "A fractional CISO or compliance consultant runs five figures a month — before the audit and pentest invoices land." },
            { icon: Clock, t: "It's point-in-time", d: "You pay for a snapshot. The day after the report, your code and cloud have already moved on." },
            { icon: RefreshCw, t: "You still do the legwork", d: "The consultant hands you findings and a checklist. Your team is the one that actually fixes and gathers evidence." },
          ].map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-surface-2 text-muted"><Icon className="h-4 w-4" /></span>
              <h3 className="mt-3 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* The split — repeatable vs judgment */}
      <section className="bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">How we do it</span>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Automate the repeatable. Keep the human for judgment.</h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              We don&apos;t pretend a machine should accept your risk or sign your audit. We automate the labor and put
              a named expert exactly where accountability belongs.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            {SPLIT.map(({ icon: Icon, head, items }) => (
              <div key={head} className="card p-6">
                <div className="flex items-center gap-2 text-sm font-semibold text-accent">
                  <Icon className="h-4 w-4" /> {head}
                </div>
                <ul className="mt-4 space-y-2.5 text-sm text-ink">
                  {items.map((x) => (
                    <li key={x} className="flex items-start gap-2.5">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Comparison */}
      <section className="mx-auto max-w-4xl px-5 py-20">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The difference</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Same outcome. Different economics.</h2>
        </div>
        <div className="overflow-hidden rounded-2xl border border-border">
          <div className="grid grid-cols-3 bg-surface text-xs font-semibold uppercase tracking-wider text-muted">
            <div className="px-4 py-3" />
            <div className="px-4 py-3 text-center">Traditional consultant</div>
            <div className="px-4 py-3 text-center text-accent">TensorShield</div>
          </div>
          {COMPARE.map((row, i) => (
            <div key={row.label} className={`grid grid-cols-3 text-sm ${i % 2 ? "bg-surface/40" : ""}`}>
              <div className="px-4 py-3 font-medium text-ink">{row.label}</div>
              <div className="flex items-center justify-center gap-1.5 px-4 py-3 text-center text-muted">
                <Minus className="h-3.5 w-3.5 shrink-0 text-faint" /> {row.consultant}
              </div>
              <div className="flex items-center justify-center gap-1.5 px-4 py-3 text-center text-ink">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-pulse" /> {row.us}
              </div>
            </div>
          ))}
        </div>
        <p className="mt-4 text-center text-xs text-faint">
          Honest version: we replace the repeatable bulk of the work, not the human judgment. For complex,
          bespoke advisory, a great consultant still earns their fee — and many run their whole practice on us.
        </p>
      </section>

      {/* Who provides the human */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <div className="mx-auto mb-10 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Two ways to get the human</span>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Use our expert, or bring your own.</h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="card p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-accent"><UserCheck className="h-4 w-4" /> We provide the expert</div>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                No security team? We supply the named vCISO, auditor liaison, and pentester who make the judgment
                calls on your behalf — every decision signed and accountable. Built for founders.
              </p>
              <Link href="/demo" className="mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
                Use us as your team <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
            <div className="card p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-accent"><FileCheck2 className="h-4 w-4" /> You bring the expert</div>
              <p className="mt-2 text-sm leading-relaxed text-muted">
                Already have a consultancy or an in-house lead? They run the human-in-the-loop from one console
                across every client — far more clients, far less busywork.
              </p>
              <Link href="/partners" className="mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
                For MSPs &amp; consultancies <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Get the consultant outcome, starting today.</h2>
          <p className="mx-auto mt-3 max-w-md text-white/75">Connect your stack and see your security &amp; compliance posture in minutes — free.</p>
          <Link href="/signup" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
