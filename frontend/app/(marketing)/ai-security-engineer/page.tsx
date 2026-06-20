import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import {
  Bot, ArrowRight, ScanLine, Filter, Wrench, FileCheck2, Fingerprint,
  UserCheck, ShieldCheck, GitPullRequest, Power, ScrollText, CheckCircle2, XCircle, Minus,
} from "lucide-react";

export const metadata = pageMeta({
  title: "Your AI security engineer — detects, triages, fixes, with you in the loop | TensorShield",
  description:
    "Not another scanner. An AI security engineer that runs the whole loop on best-in-class OSS — detect, triage real risk from noise, prepare the fix, and prove it — applying anything consequential only after you approve.",
  path: "/ai-security-engineer",
});

// What the agent actually does, end to end.
const LOOP = [
  { icon: ScanLine, t: "Detects", d: "On a deterministic floor of 30+ OSS scanners across code, cloud, web, APIs, containers, identity & SaaS — recall no model can undercut." },
  { icon: Filter, t: "Triages", d: "Separates real, exploitable risk from scanner noise — verifying, corroborating, and chaining findings into the attack paths that actually matter." },
  { icon: Wrench, t: "Fixes", d: "Prepares the real remediation — a pull request, a config change, an identity action, a ticket — ready to ship the moment you say go." },
  { icon: FileCheck2, t: "Proves", d: "Maps every finding to the controls it touches across 14 frameworks and signs it into a tamper-evident evidence pack — for your auditor and your customers." },
];

// Why it's trustworthy — the guardrails that make an autonomous agent safe.
const GUARDRAILS = [
  { icon: Fingerprint, t: "Grounded — it can't hallucinate", d: "The agent can't record a finding no tool supports, or assert a permission the evaluator didn't return. Every claim cites the evidence that proves it. No invented vulnerabilities." },
  { icon: UserCheck, t: "Human in the loop, by tier", d: "Low-risk fixes auto-apply; anything consequential waits for one tap of your approval. The autonomy is earned, never assumed — and tuned per action class." },
  { icon: GitPullRequest, t: "It ships the fix, read-only until you say so", d: "Connections are least-privilege and read-only by default. The agent opens the PR / drafts the change and applies it only after the gate — never a surprise write." },
  { icon: ScrollText, t: "Every decision is signed", d: "Auto-applied and human-approved actions alike record into a replayable, ed25519-signed ledger. You can audit exactly what the agent did, and why." },
  { icon: Power, t: "One kill-switch, fail-closed", d: "Freeze all autonomous action for the whole tenant instantly. The switch beats any verdict; queued actions wait. The one human on the loop stays in control." },
  { icon: ShieldCheck, t: "On best-in-class OSS", d: "The detection floor is the leading open-source tools the industry already trusts. The agent reasons on top — it doesn't replace proven scanners with a black box." },
];

const COMPARE: { label: string; cells: string[] }[] = [
  { label: "Best-in-class OSS detection underneath", cells: ["yes", "part", "yes"] },
  { label: "Triages real risk from noise (not a 400-row dump)", cells: ["yes", "no", "part"] },
  { label: "Prepares + ships the actual fix", cells: ["yes", "no", "no"] },
  { label: "Human-in-the-loop gate + kill-switch", cells: ["yes", "no", "no"] },
  { label: "Grounded — no hallucinated findings", cells: ["yes", "part", "no"] },
  { label: "Signed, replayable decision ledger", cells: ["yes", "no", "no"] },
  { label: "Cost for an SMB", cells: ["$/mo", "$/mo", "$$$$/yr"] },
];

export default function AISecurityEngineer() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Bot className="h-3.5 w-3.5 text-accent" /> The agentic layer
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Meet your AI security engineer.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            A scanner hands you a list. TensorShield gives you an engineer: it runs best-in-class OSS detection, triages
            the real risk from the noise, prepares the fix, and proves it — applying anything consequential only after
            you approve. No security hire required.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Put it to work <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See the platform
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">OSS-grade detection · AI triage &amp; fixes · human-in-the-loop · signed</p>
        </div>
      </section>

      {/* The loop */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">What it does</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">It runs the whole loop — so you don&apos;t.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            The work a security engineer would do, continuously: detect, triage, fix, prove. You step in only where
            judgment is needed.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {LOOP.map(({ icon: Icon, t, d }, i) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <Icon className="h-5 w-5" />
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
                  <Icon className="h-4 w-4" />
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
                  <Icon className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">STEP {step}</span>
              </div>
              <h3 className="mt-4 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

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
