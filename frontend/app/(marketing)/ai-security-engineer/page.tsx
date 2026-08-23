import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import { AgenticActions } from "@/components/marketing/agentic-actions";
import { AttackPathHero } from "@/components/marketing/attack-path-hero";
import {
  Bot, ArrowRight, ScanLine, Filter, Wrench, FileCheck2, Fingerprint,
  UserCheck, ShieldCheck, GitPullRequest, Power, ScrollText, CheckCircle2, XCircle, Minus,
} from "lucide-react";
import { FRAMEWORK_COUNT } from "@/lib/frameworks";

export const metadata = pageMeta({
  title: "AI Security Engineer — the fix arrives written",
  description:
    "It reads the noise so you don't, works out which handful of issues an attacker could actually use, and writes the change to close them. You approve; nothing moves without you.",
  path: "/ai-security-engineer",
});

// What the agent actually does, end to end.
// EACH CARD ENDS ON THE CONSEQUENCE, NOT THE MECHANISM. "30+ open-source scanners" is a fact about
// us; "you are not missing things a standalone tool would have caught" is the same fact told to the
// person paying. If a card's last clause describes how it works, it is not finished.
const LOOP = [
  { icon: ScanLine, t: "It looks everywhere, every day", d: "Code, cloud, web, APIs, containers, identity and SaaS — on a floor of 30+ open-source scanners, so you are not quietly missing what a dedicated tool would have caught." },
  { icon: Filter, t: "It tells you which five matter", d: "Hundreds of alerts become a handful, because it works out which ones an attacker could really use and what they reach. You stop guessing which are real." },
  { icon: Wrench, t: "It writes the change", d: "A pull request, a config change, an access revocation — the actual fix, not remediation advice you still have to implement. It is ready the moment you say go." },
  { icon: FileCheck2, t: "The evidence is already made", d: `The same work counts toward ${FRAMEWORK_COUNT} frameworks, signed and dated. So the answer to your customer's questionnaire is written before they ask.` },
];

// Why it's trustworthy — the guardrails that make an autonomous agent safe.
// THE REASSURANCE LAYER, AND IT IS ALLOWED TO BE PRECISE — but the card TITLE is what a sceptical
// reader scans, so the title says what it means for them and the body keeps the mechanism intact.
// "Grounded" and "tier-gated" are our words for these; nobody arrives already knowing them.
const GUARDRAILS = [
  { icon: Fingerprint, t: "You never chase a ghost", d: "It cannot report something it could not prove — no finding without a tool behind it, no claim about your permissions the evaluator did not actually return. If it cannot show you the evidence, you never see the finding." },
  { icon: UserCheck, t: "Routine fixes just happen. Risky ones wait for you", d: "The low-stakes work goes through on its own so it stops piling up. Anything that could break something sits in your inbox until you tap approve — and you set where that line is." },
  { icon: GitPullRequest, t: "It cannot write to anything until you let it", d: "Every connection is read-only by default and least-privilege. It opens the pull request or drafts the change, and applies it only after you approve. There is no surprise write." },
  { icon: ScrollText, t: "You can show exactly what it did", d: "Every action — the ones you approved and the ones that went through on their own — is recorded in a signed log you can replay. Useful the day an auditor asks, and the day you want to know why something changed." },
  { icon: Power, t: "One switch stops everything", d: "Freeze all autonomous action instantly, and it stays frozen: the switch beats any approval already given, and queued work waits. The one human on the loop stays in control." },
  { icon: ShieldCheck, t: "The detection is the tools your engineers already trust", d: "Underneath is the leading open source the industry runs on. The agent reasons on top of proven scanners rather than replacing them with something nobody can inspect." },
];

const COMPARE: { label: string; cells: string[] }[] = [
  { label: "Detection on the open source your engineers already trust", cells: ["yes", "part", "yes"] },
  { label: "Tells you which five matter, not all four hundred", cells: ["yes", "no", "part"] },
  { label: "Writes the fix, not remediation advice", cells: ["yes", "no", "no"] },
  { label: "You approve anything risky — and can stop it all instantly", cells: ["yes", "no", "no"] },
  { label: "Never reports what it could not prove", cells: ["yes", "part", "no"] },
  { label: "Shows exactly what changed, when, and who approved it", cells: ["yes", "no", "no"] },
  { label: "Cost for an SMB", cells: ["$/mo", "$/mo", "$$$$/yr"] },
];

export default function AISecurityEngineer() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Bot className="h-3.5 w-3.5 text-accent" /> Your AI security engineer
          </span>
          {/* The headline is the OFFER, not the machinery. It used to read "Meet your AI security
              engineer" — an introduction, which asks the reader to work out what they get. What they
              get is that the work arrives done. Grounding, tiers and the kill-switch are why they can
              trust it, and trust is the SECOND question a visitor has; it is answered three sections
              down, where it is asked. */}
          <h1 className="mt-6 text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            The fix arrives written. You just say yes.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Every other tool hands you a list and leaves the work with you. This one reads the noise so you don&apos;t,
            works out the handful of issues an attacker could actually use, and writes the change that closes them —
            as a pull request you approve, or not. Nothing ships without you.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Put it to work <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See the platform
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">You approve every change · It never reports what it could not prove · One switch stops it all</p>
        </div>

        {/* The cross-surface attack path, rehoused.
            This graph was the homepage hero for a long time, where it asked a founder with a blocked
            deal to parse a node graph before they felt anything. It belongs HERE — a reader on this
            page has clicked through to the mechanics and wants exactly this: how a leaked key in code
            and a stolen SaaS login become one route to cloud root, and where the engineer cuts it. */}
        <div className="relative mx-auto max-w-3xl px-5 pb-16">
          <AttackPathHero />
          <p className="mt-3 text-center text-xs leading-relaxed text-faint">
            This is the reasoning the engineer does across your estate — one route, not three
            unrelated tickets.
          </p>
        </div>
      </section>

      {/* The loop */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What it does</span>
          <h2 className="mt-3 text-balance text-3xl font-semibold leading-tight tracking-tight">The job you would hire for, done every day.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Not a tool your team has to operate — the work itself, running continuously. You step in only where a
            judgment call is genuinely yours to make.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {LOOP.map(({ icon: Icon, t, d }, i) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <FeatureIcon name={Icon.displayName} className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">{String(i + 1).padStart(2, "0")}</span>
              </div>
              <h3 className="mt-4 text-base font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Guardrails */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why you can trust it</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Autonomy you can actually hand the keys to.</h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              An agent that changes your infrastructure has to be safe by construction. Here&apos;s how.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {GUARDRAILS.map(({ icon: Icon, t, d }) => (
              <div key={t} className="card bg-bg p-5">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <FeatureIcon name={Icon.displayName} className="h-4 w-4" />
                </span>
                <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* A finding's journey */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How a fix happens</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">From scanner output to a signed, approved fix.</h2>
        </div>
        <div className="grid gap-5 md:grid-cols-4">
          {[
            { step: "1", icon: ScanLine, t: "A tool fires", d: "An OSS scanner surfaces a candidate. It enters the agent's queue grounded in that tool's evidence." },
            { step: "2", icon: Filter, t: "The agent verifies", d: "It confirms, corroborates across tools, and rates confidence — discarding what it can't substantiate." },
            { step: "3", icon: Wrench, t: "It writes the fix", d: "A PR, config change, or identity action — mapped to the CWE and the compliance controls it closes." },
            { step: "4", icon: CheckCircle2, t: "You approve", d: "Consequential changes wait for your tap. It applies, then signs the decision into the ledger." },
          ].map(({ step, icon: Icon, t, d }) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <FeatureIcon name={Icon.displayName} className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">STEP {step}</span>
              </div>
              <h3 className="mt-4 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* The interaction model — one-click agentic actions, not a chat box (the in-app console). */}
      <AgenticActions />

      {/* Compare */}
      <section className="bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Vs the alternatives</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">A scanner flags. An engineer fixes.</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] border-separate border-spacing-0 text-sm">
              <thead>
                <tr>
                  <th className="w-[40%] p-0" />
                  {[
                    { name: "TensorShield", sub: "AI security engineer", highlight: true },
                    { name: "A scanner", sub: "flags only", highlight: false },
                    { name: "Hire an engineer", sub: "$150k+/yr", highlight: false },
                  ].map((c) => (
                    <th key={c.name} className={`rounded-t-xl px-4 py-3 text-center align-bottom ${c.highlight ? "bg-accent-soft/60 ring-1 ring-accent/30" : ""}`}>
                      <div className={`text-sm font-semibold ${c.highlight ? "text-accent" : "text-ink"}`}>{c.name}</div>
                      <div className="mt-0.5 text-[11px] font-normal text-faint">{c.sub}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {COMPARE.map((r, ri) => (
                  <tr key={r.label}>
                    <td className="border-t border-border py-3 pr-4 text-sm text-ink">{r.label}</td>
                    {r.cells.map((v, ci) => (
                      <td key={ci} className={`border-t border-border px-4 py-3 text-center ${ci === 0 ? "bg-accent-soft/30" : ""} ${ri === COMPARE.length - 1 ? "rounded-b-xl" : ""}`}>
                        <Cell v={v} highlight={ci === 0} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-4 text-center text-[11px] text-faint">Category comparison — capabilities vary by vendor and plan.</p>
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Hire the engineer that never sleeps.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect a system and watch the agent detect, triage, and prepare its first fixes — for free, with you in
            control of anything that matters.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/security" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              How we keep it safe
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}

function Cell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <CheckCircle2 className={`mx-auto h-5 w-5 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <XCircle className="mx-auto h-5 w-5 text-faint/60" />;
  if (v === "part") return <Minus className="mx-auto h-5 w-5 text-amber-500/70" />;
  return <span className={`text-sm font-semibold ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}
