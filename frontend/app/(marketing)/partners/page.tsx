import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  Building2, ArrowRight, TrendingUp, UserCog, Layers, ShieldCheck, Briefcase,
  Clock, BadgeCheck, Wallet, CheckCircle2,
} from "lucide-react";

export const metadata = pageMeta({
  title: "For MSPs & security consultancies — deliver more, hire less | TensorShield",
  description:
    "Run security & compliance for your whole book of clients on TensorShield. The AI does the labor — scanning, fixing, evidence, monitoring — and your experts handle the judgment from one console. More clients per expert, your brand, your accountability.",
  path: "/partners",
});

const PAINS = [
  { icon: Clock, t: "Your margin dies in the busywork", d: "Scanning, chasing evidence, writing the same remediation tickets, watching dashboards — your senior people spend their hours on work a machine should do." },
  { icon: UserCog, t: "You can't hire experts fast enough", d: "Every new client needs a vCISO's, an auditor's, a pentester's time. Growth is capped by headcount you can't find or afford." },
  { icon: Layers, t: "Every client is a separate fire drill", d: "Logging into ten tools across thirty clients, with no single view of what actually needs your judgment today." },
];

const GAINS = [
  { icon: TrendingUp, t: "More clients per expert", d: "The AI runs detection, remediation, evidence, and monitoring continuously across every client. Your experts stop doing the labor and only make the calls that need a human." },
  { icon: Building2, t: "Your brand, your relationship", d: "White-label the work. The client sees your firm; you keep the trusted-advisor relationship and the accountability. We're the engine underneath." },
  { icon: Wallet, t: "Higher margin, lower risk", d: "Deliver the same outcomes at a fraction of the labor cost — and every decision is signed and ledgered with your expert's name, so accountability is airtight." },
];

const STEPS = [
  { n: "1", t: "Onboard your clients", d: "Connect each client's code, cloud, and identity. The agent discovers their assets and starts working immediately — no per-client tooling to stand up." },
  { n: "2", t: "The AI does the labor", d: "Continuous scanning, prioritized fixes as pull requests and config changes, signed compliance evidence, and 24/7 monitoring — across your whole book." },
  { n: "3", t: "Your expert works one queue", d: "A single cross-tenant console shows every client's pending judgment calls — a risk to accept, a control to attest, a pentest to sign off, a policy to publish — scoped to the clients you're assigned." },
  { n: "4", t: "Every call is named and signed", d: "Your expert decides; the decision is recorded with their name, their capacity, and your firm, and signed into a tamper-evident ledger. Audit-ready by construction." },
];

export default function Partners() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Briefcase className="h-3.5 w-3.5 text-accent" /> For MSPs, MSSPs &amp; security consultancies
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Serve more clients. <span className="text-accent">Hire fewer experts.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Run security &amp; compliance for your entire book of clients on TensorShield. The AI does the heavy
            lifting; your experts make the judgment calls that matter — all from one console, under your brand.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Become a partner <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See the platform
            </Link>
          </div>
        </div>
      </section>

      {/* The pain */}
      <section className="mx-auto max-w-6xl px-5 py-16">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The problem</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Consulting doesn&apos;t scale — until the labor does.</h2>
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
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">The shift</span>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight">Put the busywork on autopilot. Keep the judgment.</h2>
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

      {/* How it works */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">One console for your whole book.</h2>
        </div>
        <ol className="space-y-3">
          {STEPS.map(({ n, t, d }) => (
            <li key={n} className="card flex gap-4 p-5">
              <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-accent text-sm font-semibold text-white">{n}</span>
              <div>
                <h3 className="text-sm font-semibold">{t}</h3>
                <p className="mt-1 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* Trust strip */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto grid max-w-5xl gap-4 px-5 py-10 sm:grid-cols-3">
          {[
            { icon: BadgeCheck, t: "Named accountability", d: "Every decision carries your expert's name + your firm, signed into the ledger." },
            { icon: ShieldCheck, t: "Client isolation, enforced", d: "Your expert only ever sees the clients they're assigned — never another firm's, never a client they don't serve." },
            { icon: CheckCircle2, t: "Built on best-in-class OSS", d: "The same open-source security tools the best teams trust, orchestrated — not a black box." },
          ].map(({ icon: Icon, t, d }) => (
            <div key={t} className="flex items-start gap-3">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent"><FeatureIcon name={Icon.displayName} className="h-4 w-4" /></span>
              <div>
                <div className="text-sm font-semibold">{t}</div>
                <div className="mt-0.5 text-xs leading-snug text-muted">{d}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Grow your practice without growing your headcount.</h2>
          <p className="mx-auto mt-3 max-w-md text-white/75">Let&apos;s map your client book to TensorShield and show you the margin math.</p>
          <Link href="/demo" className="mt-7 inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Become a partner <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </>
  );
}
