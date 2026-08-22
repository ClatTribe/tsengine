import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  Rocket, ArrowRight, Ban, Users, Wallet, FileCheck, ShieldCheck, RefreshCw,
  CheckCircle2, Clock,
} from "lucide-react";

// The ICP page. Every other segment page we had was a CHANNEL page — /partners for MSPs, /managed
// for the done-for-you model — and the customer we actually build for had none. A Series A B2B SaaS
// team hitting its first enterprise security review could arrive on this site and find no page that
// described their situation back to them.
//
// It leads with the trigger rather than the product because at this stage nobody wakes up wanting
// security: they want a specific deal to stop being stuck. The three pains below are the three
// purchases that moment normally forces (a pentest firm, a compliance tool, and a retest nobody
// books), which is what makes "one artifact" the argument rather than a feature list.
//
// Every claim here is one the product actually makes elsewhere on the site — exploitation-proven
// findings, a named human signing the report, retest after the fix, the free tier running on your
// own LLM key. Nothing is asserted here that isn't true on /ai-pentest, /vapt or /pricing.
export const metadata = pageMeta({
  title: "Security for Series A and B startups — pass the review, keep the deal | TensorShield",
  description:
    "An enterprise customer's security review is blocking your deal and security is nobody's full-time job yet. Get an exploitation-proven pentest report, the compliance evidence the questionnaire asks for, and proof the fixes landed — signed by a named human. Start free.",
  path: "/startups",
});

const PAINS = [
  {
    icon: Ban,
    t: "A deal is stuck behind a security review",
    d: "Your biggest prospect sent a questionnaire, or asked for a pentest report you don't have. The deal doesn't move until you produce one, and nobody on the team has done this before.",
  },
  {
    icon: Users,
    t: "There's no one to hand it to",
    d: "You have engineers, not a security team. The work lands on whoever has least to do this week, which is nobody, so it lands on the CTO.",
  },
  {
    icon: Wallet,
    t: "It's three purchases, not one",
    d: "A pentest firm for the report, a compliance tool for the evidence, and a retest nobody ever books. Three vendors, three renewals, and the report is stale the week after it lands.",
  },
];

const GAINS = [
  {
    icon: FileCheck,
    t: "One artifact, not three vendors",
    d: "The findings, the evidence mapped to the controls the questionnaire asks about, and the proof the fix worked — produced together, from the same run, instead of bought from three places.",
  },
  {
    icon: ShieldCheck,
    t: "Proven, not flagged",
    d: "Nothing reaches the report unless it was reproduced. There's no 'possible' or 'medium confidence' padding for the reviewer on the other side to pick at — and a named human signs it, which is what that reviewer is actually checking for.",
  },
  {
    icon: RefreshCw,
    t: "It stays true after you ship",
    d: "A once-a-year pentest is out of date by the next deploy. This re-tests after every fix and keeps running, so the next questionnaire is mostly already answered.",
  },
];

const STEPS = [
  { n: "1", t: "Connect GitHub and your cloud, read-only", d: "No agents to install, no changes to your infrastructure. Takes minutes." },
  { n: "2", t: "Get real findings the same day", d: "Not a list of maybes — the ones that were reproduced, ranked by what they actually reach." },
  { n: "3", t: "Fix, then prove it", d: "The fix comes as a pull request you approve. Then it's re-tested, so 'fixed' means verified rather than assumed." },
  { n: "4", t: "Send the report", d: "The VAPT report and the control evidence, signed by a named practitioner, ready to attach to the questionnaire." },
];

export default function Page() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Rocket className="h-3.5 w-3.5 text-accent" /> For Series A and B teams stretched thin on security
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            The security review is blocking the deal. <span className="text-accent">Unblock it.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            An enterprise customer wants a pentest report and answers to a questionnaire you&apos;ve never seen
            before. You get both from one place — with the findings actually proven, and a named human standing
            behind the report.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/sample-report" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See a sample report
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">
            No credit card · connect read-only ·{" "}
            <Link href="/scan" className="text-accent hover:underline">
              or check your domain first, free
            </Link>
          </p>
        </div>
      </section>

      {/* The pain */}
      <section className="mx-auto max-w-6xl px-5 py-16">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The situation</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Nobody buys security at Series A. They buy the deal back.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {PAINS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-surface-2 text-muted"><FeatureIcon name={Icon.displayName} className="h-4 w-4" /></span>
              <h3 className="mt-3 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* The gain */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">What changes</span>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">The report, the evidence, and the proof it got fixed.</h2>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            {GAINS.map(({ icon: Icon, t, d }) => (
              <div key={t} className="card p-6">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent"><FeatureIcon name={Icon.displayName} className="h-5 w-5" /></span>
                <h3 className="mt-4 text-base font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it goes */}
      <section className="mx-auto max-w-4xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it goes</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Connected today, report in hand this week.</h2>
        </div>
        <ol className="space-y-4">
          {STEPS.map(({ n, t, d }) => (
            <li key={n} className="card flex gap-4 p-5">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-accent-soft text-sm font-semibold text-accent">{n}</span>
              <div>
                <h3 className="text-sm font-semibold">{t}</h3>
                <p className="mt-1 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Cost honesty */}
      <section className="bg-surface">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What it costs you now</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Start on the free plan.</h2>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            The free plan runs the full scanning engine across your code, cloud, and perimeter. Paste
            in your own LLM key and both AI agents — the security engineer and the pentester — run on it too, at
            your model cost, with no upgrade and no sales call.
          </p>
          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/pricing" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See pricing
            </Link>
          </div>
          <ul className="mx-auto mt-8 grid max-w-lg gap-2 text-left text-sm text-muted sm:grid-cols-2">
            {[
              "No credit card to start",
              "Read-only access, no agents",
              "Your own LLM key works on Free",
              "A named human signs the report",
            ].map((x) => (
              <li key={x} className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" />
                {x}
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Closing */}
      <section className="mx-auto max-w-3xl px-5 py-20 text-center">
        <Clock className="mx-auto h-8 w-8 text-accent" />
        <h2 className="mt-4 text-3xl font-semibold tracking-tight">If the review has a date on it, tell us the date.</h2>
        <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
          We&apos;ll tell you honestly whether we can make it. If we can&apos;t, we&apos;ll say so.
        </p>
        <Link href="/demo" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
          Talk to us <ArrowRight className="h-4 w-4" />
        </Link>
      </section>
    </>
  );
}
