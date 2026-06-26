import Link from "next/link";
import { ArrowRight, UserCheck, ShieldCheck, FileSignature, Crosshair, ClipboardCheck, Clock, Wallet, CheckCircle2 } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { FaqJsonLd } from "@/components/marketing/faq-jsonld";

export const metadata = pageMeta({
  title: "Managed Security & Compliance — Fractional CISO for Startups | TensorShield",
  description:
    "We run your security and compliance for you — a named vCISO, pentester, and auditor liaison backed by the product. Done-for-you SOC 2, continuous security, and named accountability, for a fraction of one hire.",
  path: "/managed",
});

const INCLUDED = [
  { icon: ShieldCheck, t: "A named vCISO", d: "A seasoned security leader owns your program — risk decisions, policy, and the judgment calls a tool can't make. Not a chatbot; a person who signs their name." },
  { icon: Crosshair, t: "Pentests with accountability", d: "Exploitation-proven testing on your assets, with a named human signing off on the report your customers and auditors will read." },
  { icon: FileSignature, t: "Auditor liaison", d: "We prep the controls and evidence and quarterback the independent auditor through the SOC 2 / ISO engagement — the attestation stays theirs, by law." },
  { icon: ClipboardCheck, t: "The product, running underneath", d: "Continuous scanning across your code, cloud, apps, and identity does the heavy lifting — so the expert spends their time on judgment, not busywork." },
];

const STEPS = [
  { t: "Connect your stack", d: "Read-only access to your code, cloud, identity, and apps. The product maps every asset and starts scanning in minutes." },
  { t: "We run it for you", d: "Your named expert triages the findings, approves the fixes, writes the policies, and makes the risk calls — every decision signed into an auditable ledger." },
  { t: "You stay audit-ready", d: "Live posture across 22 frameworks, a current evidence pack, and a vCISO on call — so a customer questionnaire or an auditor request is a non-event." },
];

const VS = [
  { icon: Wallet, t: "vs. a full-time hire", d: "A senior security hire is $200k+ and months to find. You get the same coverage — leadership, testing, compliance — for a fraction, starting now." },
  { icon: Clock, t: "vs. a traditional consultant", d: "A consultant hands you a PDF and a retainer. We run it continuously: the product does the work between reviews, so nothing goes stale the day they leave." },
  { icon: UserCheck, t: "vs. doing it yourself", d: "No security team to hire, train, or pull off the roadmap. The expert and the platform are the team — you keep building." },
];

const FAQ: [string, string][] = [
  ["What exactly do you do for me?", "We run your security and compliance end to end: continuous scanning across your stack, a named vCISO who owns the program and the risk decisions, exploitation-proven pentests with named sign-off, and an auditor liaison who gets you through SOC 2 / ISO. You get the outcome without hiring a team."],
  ["Do you certify or audit me yourselves?", "No — and that's deliberate. A SOC 2 / ISO attestation must come from an independent licensed auditor (it's a legal requirement). We make you audit-ready and quarterback the engagement; the auditor renders the opinion. We're honest about that line."],
  ["How is this different from your self-serve product?", "Same product, but you don't run it — we do. The human-in-the-loop (the judgment, the policy, the sign-off) is our named expert acting on your behalf, instead of your team. If you have a security person, self-serve is cheaper; if you don't, managed is the team."],
  ["Who is accountable for the work?", "A named person. Every risk decision, pentest report, policy, and attestation carries the signer's name and is recorded in a signed ledger — so there's real, traceable accountability, not an anonymous dashboard."],
  ["What does it cost?", "Far less than a full-time senior hire ($200k+) and without the months-long search. Pricing depends on your stack and frameworks — book a call and we'll scope it."],
  ["Can you get me SOC 2 fast?", "We get you audit-ready quickly by automating the technical controls and evidence, then running the manual areas (policies, attestations) with our expert. The audit timeline itself is the auditor's, but you stop being the bottleneck."],
];

export default function Managed() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative mx-auto max-w-3xl animate-fade-rise px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <UserCheck className="h-3.5 w-3.5 text-accent" /> Managed security &amp; compliance
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Your security team and compliance department — without the hires.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            We run it for you. A named vCISO, a pentester, and an auditor liaison — backed by a product that scans
            your whole stack continuously — get you secure and audit-ready and keep you there. For a fraction of one
            senior hire, starting now.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Book a scoping call <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              Free instant check
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">Named, accountable experts · SOC 2 · ISO 27001 · pentests · continuous coverage</p>
        </div>
      </section>

      {/* What's included */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What you get</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">A whole security function, run for you.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {INCLUDED.map((c) => (
            <div key={c.t} className="card p-5">
              <c.icon className="h-5 w-5 text-accent" />
              <div className="mt-3 text-sm font-semibold text-ink">{c.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{c.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section className="mx-auto max-w-5xl px-5 py-14">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">You build. We run security &amp; compliance.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {STEPS.map((s, i) => (
            <div key={s.t} className="card p-5">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent-soft text-sm font-semibold text-accent">{i + 1}</div>
              <div className="mt-3 text-sm font-semibold text-ink">{s.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{s.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Why managed */}
      <section className="mx-auto max-w-5xl px-5 pb-4">
        <div className="mx-auto mb-8 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why managed</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">The outcome of a team, without the cost of one.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-3">
          {VS.map((v) => (
            <div key={v.t} className="card p-5">
              <v.icon className="h-5 w-5 text-accent" />
              <div className="mt-3 text-sm font-semibold text-ink">{v.t}</div>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{v.d}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 rounded-xl border border-border bg-surface p-5 text-center text-sm leading-relaxed text-muted">
          The judgment stays human — a named vCISO, a named pentester, a named auditor. The difference from
          doing it yourself is simply that the human is <span className="font-medium text-ink">ours</span>, working on your behalf.
          Prefer to bring your own expert, or you&apos;re an MSP serving clients? <Link href="/partners" className="text-accent hover:underline">See the partner model</Link>.
        </div>
      </section>

      {/* FAQ */}
      <section className="mx-auto max-w-3xl px-5 py-14">
        <h2 className="mb-8 text-center text-3xl font-semibold leading-tight tracking-tight">Frequently asked</h2>
        <div className="space-y-3">
          {FAQ.map(([q, a]) => (
            <div key={q} className="card p-5">
              <div className="flex items-start gap-2 text-sm font-semibold text-ink">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent" /> {q}
              </div>
              <p className="mt-2 pl-6 text-sm leading-relaxed text-muted">{a}</p>
            </div>
          ))}
        </div>
        <FaqJsonLd items={FAQ} />
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-3xl px-5 pb-24 text-center">
        <div className="rounded-2xl border border-border bg-surface p-10">
          <h2 className="text-2xl font-semibold tracking-tight">Stop being your own security team.</h2>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-muted">
            Book a 30-minute scoping call. We&apos;ll map your stack, your target frameworks, and what &ldquo;run it
            for me&rdquo; costs — then your named expert takes it from there.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/demo" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover">
              Book a scoping call <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/pricing" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See pricing
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
