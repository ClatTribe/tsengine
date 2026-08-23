import Link from "next/link";
import { FeatureIcon } from "@/components/brand/feature-icon";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";
import {
  Spline, ArrowRight, Layers, GitMerge, EyeOff, ShieldCheck, Crown, Boxes, Workflow, Radar,
} from "lucide-react";

export const metadata = pageMeta({
  title: "Attack paths across code, cloud and SaaS",
  description:
    "Three tools each say \u201cmedium\u201d and nobody says they are one way in. We join them into the route an attacker would take, and show you where to cut it.",
  path: "/cross-detection",
});

// What the unified platform actually does — each maps to a shipped capability.
const PILLARS = [
  {
    icon: Layers, t: "One issue, not three tickets",
    d: "When three scanners flag the same thing you get one row — and the fact that three tools agree becomes a reason to believe it, instead of three copies of the same job. Your queue gets shorter and more trustworthy at once.",
  },
  {
    icon: Spline, t: "The chain nobody else joins up",
    d: "A key in code, an exposed host, an over-privileged cloud role: on their own, three mediums sitting in three different tools. Together they are one route into your cloud account — and you see it as one route, not as three unrelated tickets.",
  },
  {
    icon: EyeOff, t: "A queue you can actually finish",
    d: "What several tools agree on rises to the top and duplicates fold away. Dismiss something as a false positive, or accept the risk with a reason, and it leaves your list — recorded and reversible, never quietly deleted.",
  },
  {
    icon: Radar, t: "What someone is trying right now",
    d: "If a sensor in your app sees a real attack land on one of your endpoints, we match it to the issue behind it and move that issue to the front. Someone actually trying it is the strongest evidence there is that it matters today.",
  },
];

// The grounded "why you can trust the connections" guardrails.
const GROUNDING = [
  { icon: ShieldCheck, t: "A line is only drawn when it is real", d: "Two findings are joined when they genuinely share something concrete — the same key, the same ARN, the same host. Never because they looked related. A guessed connection sends you to fix the wrong thing." },
  { icon: GitMerge, t: "Detection your engineers can inspect", d: "Underneath is the leading open source the industry already runs. We connect what those tools proved; we do not add a detector nobody can look inside." },
  { icon: Crown, t: "It ends at what you would hate to lose", d: "A path stops at something that matters — an account with admin access, a route to your customer data — so what you are reading is how bad it gets, not how many rows there are." },
  { icon: Boxes, t: "Everything you run, in one list", d: "Code, dependencies, containers, cloud, web, APIs, identity and SaaS — found, scanned and joined up in one ranked view instead of eight tabs." },
];

export default function CrossDetection() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Workflow className="h-3.5 w-3.5 text-accent" /> Cross-surface attack paths
          </span>
          {/* Named after the consequence, not after the machinery that produces it. "Cross-surface
              detection" is what we built; what the reader HAS is three tools all saying "medium" and
              nobody able to tell them the three are one way in. */}
          <h1 className="mt-6 text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            One leaked key is never just one leaked key.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            A key in your code. A role with more access than it needs. A host you forgot was public. Three tools each
            call one of those a medium and none of them mentions the other two — which is how a chain of mediums
            becomes the way into your whole account. We draw the line between them, and mark the hop that breaks it.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See the platform
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">One issue, not three tickets · Ranked by what it reaches · Never a guessed connection</p>
        </div>
      </section>

      {/* Pillars */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Cross-detection</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Findings are data. Connections are insight.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {PILLARS.map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-6">
              <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                <FeatureIcon name={Icon.displayName} className="h-5 w-5" />
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
                  <FeatureIcon name={Icon.displayName} className="h-4 w-4" />
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
