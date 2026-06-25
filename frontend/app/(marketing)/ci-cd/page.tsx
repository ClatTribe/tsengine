import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import { AuroraBackdrop } from "@/components/marketing/aurora";

import {
  GitMerge, ArrowRight, ShieldCheck, GitBranch, FileCode2, GaugeCircle,
  Layers, Webhook, Terminal, CircleSlash, Crosshair, Import,
} from "lucide-react";

export const metadata = pageMeta({
  title: "Security in your CI/CD pipeline — block the PR, not the team | TensorShield",
  description:
    "Run TensorShield in your pipeline: a build gate that fails only on NEW issues over your threshold, native SARIF into GitHub's Security tab, and a one-command import for the scanners you already run. Best-in-class OSS underneath.",
  path: "/ci-cd",
});

// The three things the pipeline integration actually does — each maps to a real CLI command.
const STEPS = [
  {
    icon: Terminal, step: "1", t: "Scan in the pipeline",
    d: "One command runs the same best-in-class OSS detection floor your platform uses — in your runner, on the branch, before it merges. No agent, no infra to host.",
  },
  {
    icon: GaugeCircle, step: "2", t: "The gate decides",
    d: "A policy thresholds the findings and exits non-zero only when the build should break. Annotations post inline on the PR so the diff shows exactly what failed.",
  },
  {
    icon: ShieldCheck, step: "3", t: "Results land in GitHub Security",
    d: "Export native SARIF and every finding shows up in the repo's Security tab and as PR code-scanning alerts — dedup, history, and dismissal handled by GitHub.",
  },
];

// Why the gate doesn't become the thing developers route around — each is a real flag.
const FEATURES = [
  {
    icon: GitBranch, t: "Fails on new issues, not your backlog",
    d: "--new-only diffs against a saved baseline of fingerprints, so a clean PR passes even on a repo with pre-existing debt. The gate blocks what this change introduced — nothing else.",
  },
  {
    icon: Crosshair, t: "Threshold on real risk, not raw count",
    d: "Break the build on a severity floor (--fail-on high), or only on actively-verified findings (--fail-on-verified) or reachable SCA vulnerabilities (--fail-on-reachable). Noise doesn't stop a merge.",
  },
  {
    icon: FileCode2, t: "Native SARIF — first-class in GitHub",
    d: "export --format sarif emits SARIF 2.1.0. Upload it with the standard code-scanning action and findings become PR annotations and Security-tab alerts, with GitHub's own triage on top.",
  },
  {
    icon: Import, t: "Bring the scanners you already run",
    d: "import ingests SARIF, Snyk, or Dependabot output from your existing tools — so they get the same grounding, reachability, and gate treatment without ripping anything out.",
  },
  {
    icon: Layers, t: "Budget the regression",
    d: "--max-new caps how many new findings a PR may add before the gate trips — a pragmatic middle ground while a team pays down a backlog, instead of all-or-nothing.",
  },
  {
    icon: Webhook, t: "Or stream to your own system",
    d: "export --webhook POSTs the normalized findings event to any endpoint, HMAC-signed, so a homegrown dashboard or SIEM gets the same data the platform does.",
  },
];

export default function CICD() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <AuroraBackdrop />
        <div className="relative animate-fade-rise mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <GitMerge className="h-3.5 w-3.5 text-accent" /> In your pipeline
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Security in CI/CD. Block the PR, not the team.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Run the same detection in your pipeline that the platform runs continuously — with a gate that breaks the
            build only on new issues over your threshold, and results that land natively in GitHub&apos;s Security tab.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/integrations" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
              See integrations
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">SARIF-native · new-issues-only gate · import existing scanners · runs read-only</p>
        </div>
      </section>

      {/* How it works */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Three lines in your workflow file.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Scan, gate, publish. Each step is one command — and the gate is the only thing that can fail your build.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {STEPS.map(({ icon: Icon, step, t, d }) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <Icon className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">STEP {step}</span>
              </div>
              <h3 className="mt-4 text-base font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* The actual workflow */}
      <section className="mx-auto max-w-4xl px-5 py-16">
        <div className="card overflow-hidden p-0">
          <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-4 py-2.5">
            <span className="h-2.5 w-2.5 rounded-full bg-critical/60" />
            <span className="h-2.5 w-2.5 rounded-full bg-medium/60" />
            <span className="h-2.5 w-2.5 rounded-full bg-pulse/60" />
            <span className="ml-2 font-mono text-xs text-faint">.github/workflows/security.yml</span>
          </div>
          <pre className="overflow-x-auto px-5 py-4 font-mono text-[12.5px] leading-relaxed text-ink">
{`# 1. Scan the branch (any asset: repo, image, web, api…)
tsengine scan --target . --out scan.json

# 2. Fail the build only on NEW high+ issues vs. the baseline
tsengine gate --in scan.json \\
  --fail-on high --new-only --baseline .tsengine/baseline.json \\
  --format github            # → inline PR annotations, exit 1 on fail

# 3. Publish to GitHub's Security tab
tsengine export --in scan.json --format sarif --out results.sarif
#   …then: github/codeql-action/upload-sarif@v3`}
          </pre>
        </div>
        <p className="mt-3 text-center text-[11px] text-faint">
          Every flag above is real. Run <span className="font-mono">tsengine gate --help</span> for the full policy surface.
        </p>
      </section>

      {/* Features */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why the gate sticks</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">A gate developers don&apos;t route around.</h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              A pipeline check only works if it&apos;s right more than it&apos;s annoying. The policy is built so a clean
              change passes — and only a real regression stops the merge.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, t, d }) => (
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

      {/* Shift-left framing */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="grid items-center gap-10 md:grid-cols-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Shift left, without the tax</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              The same engine, two places it runs.
            </h2>
            <p className="mt-4 text-base leading-relaxed text-muted">
              The platform watches your assets continuously and runs the autonomous agent on top. The CLI puts that same
              best-in-class OSS detection in your pipeline, so a vulnerability is caught at the pull request — not in next
              month&apos;s scan. One contract, one set of findings, two entry points.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link href="/ai-security-engineer" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-4 py-2.5 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
                The agent on top <ArrowRight className="h-4 w-4" />
              </Link>
              <Link href="/product" className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-4 py-2.5 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong">
                The platform
              </Link>
            </div>
          </div>
          <div className="grid gap-3">
            {[
              { icon: CircleSlash, t: "Runs read-only", d: "The pipeline command reads your code and dependencies. It never writes back — no tokens with push access, no surprise commits." },
              { icon: GitBranch, t: "Branch-aware baseline", d: "Save a baseline on main; diff every PR against it. Existing debt stays visible on the platform without blocking unrelated changes." },
              { icon: ShieldCheck, t: "Grounded findings only", d: "Every gate decision traces to a tool that fired. No model invents a reason to fail your build." },
            ].map(({ icon: Icon, t, d }) => (
              <div key={t} className="card flex items-start gap-3 p-4">
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <div>
                  <h3 className="text-sm font-semibold">{t}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-muted">{d}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Catch it at the pull request.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Add the gate to one workflow file and ship with security in the loop — without slowing the team down.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/integrations" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              All integrations
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
