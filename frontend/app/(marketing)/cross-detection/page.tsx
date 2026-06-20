import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import {
  Spline, ArrowRight, Layers, GitMerge, EyeOff, ShieldCheck, Crown, Boxes, Workflow,
} from "lucide-react";

export const metadata = pageMeta({
  title: "One platform, every surface — cross-detection that connects the dots | TensorShield",
  description:
    "Most tools hand you a pile of findings per scanner. TensorShield unifies them: the same issue from many scanners becomes one, weaknesses chain across surfaces into attack paths, and you triage real risk — not duplicate noise.",
  path: "/cross-detection",
});

// What the unified platform actually does — each maps to a shipped capability.
const PILLARS = [
  {
    icon: Layers, t: "One issue, many signals",
    d: "The same CVE flagged by three scanners is ONE issue, confirmed by three sources — not three rows. Findings collapse by CVE (or rule + location) into a single row carrying the worst severity and every tool that saw it.",
  },
  {
    icon: Spline, t: "Attack paths across surfaces",
    d: "A leaked key in code, an exposed host, a cloud admin role — separately they're medium findings. TensorShield bridges them on a real shared identifier into the chain that reaches a crown jewel, and shows it as one path.",
  },
  {
    icon: EyeOff, t: "Triage, not noise",
    d: "Multi-tool-confirmed issues rise to the top; the rest is de-duplicated away. Ignore a false positive or accept a risk with a reason — it's recorded, reversible, and off your queue.",
  },
];

// The grounded "why you can trust the connections" guardrails.
const GROUNDING = [
  { icon: ShieldCheck, t: "Links only on real evidence", d: "An attack-path hop is drawn only when two findings share a concrete identifier — a key, an ARN, a host. Never an inferred or guessed connection." },
  { icon: GitMerge, t: "Built on best-in-class OSS", d: "The detection underneath is the leading open-source scanners. The platform correlates on top — it adds no black-box detector, only connects what the tools already proved." },
  { icon: Crown, t: "Crown-jewel aware", d: "Paths terminate at what matters — a cloud account with admin access, a privilege-escalation finding — so you see blast radius, not just a list." },
  { icon: Boxes, t: "Every surface, one pane", d: "Code, dependencies, containers, cloud, web, APIs, identity & SaaS — discovered, scanned, and correlated into a single prioritized view." },
];

export default function CrossDetection() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Workflow className="h-3.5 w-3.5 text-accent" /> Unified platform
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Every surface. One platform. The dots, connected.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Point tools at your stack and you get a pile of findings — per scanner, per surface, duplicated and
            unranked. TensorShield unifies them: one issue from many signals, weaknesses that chain into attack
            paths, and a queue that's real risk instead of noise.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See the platform
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">cross-scanner dedup · cross-surface attack paths · grounded, never guessed</p>
        </div>
      </section>

      {/* Pillars */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Cross-detection</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Findings are data. Connections are insight.</h2>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {PILLARS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-6">
              <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                <Icon className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-base font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Attack-path illustration */}
      <section className="mx-auto max-w-4xl px-5 py-16">
        <div className="card p-6">
          <div className="mb-5 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-accent">
            <Spline className="h-4 w-4" /> A cross-surface attack path
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-stretch">
            <PathStep tag="entry · code" title="Exposed .env leaks an AWS key" tone="accent" />
            <Bridge label="aws_key" />
            <PathStep tag="cloud" title="That key is on an admin role" />
            <Bridge label="role" />
            <PathStep tag="crown jewel" title="AdministratorAccess — full account" tone="high" crown />
          </div>
          <p className="mt-4 text-xs leading-relaxed text-faint">
            Three medium findings on three surfaces. One critical path — drawn only because each hop shares a real,
            concrete identifier. That's the difference between a list and an answer.
          </p>
        </div>
      </section>

      {/* Grounding */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why you can trust it</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Connections you can trust, not correlations you can&apos;t.</h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {GROUNDING.map(({ icon: Icon, t, d }) => (
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

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Stop triaging lists. Start fixing what matters.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect your stack and watch the noise collapse into a handful of real, prioritized, connected issues.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/ai-security-engineer" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              The agent on top
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}

function PathStep({ tag, title, tone, crown }: { tag: string; title: string; tone?: "accent" | "high"; crown?: boolean }) {
  const border = tone === "high" ? "border-high/50 bg-high/5" : tone === "accent" ? "border-accent/40 bg-accent-soft/30" : "border-border bg-surface";
  return (
    <div className={`flex-1 rounded-xl border p-4 ${border}`}>
      <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-faint">
        {crown && <Crown className="h-3 w-3 text-high" />} {tag}
      </div>
      <div className="mt-1.5 text-sm font-medium leading-snug">{title}</div>
    </div>
  );
}

function Bridge({ label }: { label: string }) {
  return (
    <div className="flex shrink-0 flex-row items-center justify-center gap-1 sm:flex-col">
      <ArrowRight className="h-4 w-4 rotate-90 text-faint sm:rotate-0" />
      <span className="mono text-[9px] text-muted">{label}</span>
    </div>
  );
}
