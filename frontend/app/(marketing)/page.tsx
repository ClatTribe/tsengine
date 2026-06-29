import Link from "next/link";
import {
  ShieldCheck, Sparkles, ArrowRight, Plug, ScanLine, CheckCircle2, FileCheck2,
  Lock, Cloud, KeyRound, Star, Wrench, Mail, ClipboardCheck,
  Activity, ChevronDown, GitBranch, XCircle, Minus, Wallet,
} from "lucide-react";
import { ProviderIcon } from "@/components/brand/provider-icon";
import { LiveConsole } from "@/components/marketing/live-console";
import { Reveal } from "@/components/marketing/reveal";
import { TrustBar } from "@/components/marketing/trust-bar";
import { EngageModels } from "@/components/marketing/engage-models";
import { Prioritize } from "@/components/marketing/prioritize";
import { PlatformOverview } from "@/components/marketing/platform-overview";
import { UnifiedPlatform } from "@/components/marketing/unified-platform";
import { ArchStack } from "@/components/marketing/arch-stack";
import { AgenticActions } from "@/components/marketing/agentic-actions";

export const metadata = {
  title: "TensorShield — pass the security review, close the deal",
  description:
    "Enterprise deals stall on security questionnaires, SOC 2, and pentests. TensorShield handles all of it — finds, fixes, and proves your security, with a named expert in the loop where judgment matters. No security hire required.",
  alternates: { canonical: "/" },
};

export default function Landing() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        {/* animated aurora backdrop — modern depth, subtle motion */}
        <div className="pointer-events-none absolute inset-0">
          <div className="absolute -top-24 left-[20%] h-[26rem] w-[26rem] -translate-x-1/2 rounded-full bg-accent/20 blur-[110px] animate-aurora" />
          <div className="absolute -top-16 right-[16%] h-[22rem] w-[22rem] translate-x-1/2 rounded-full bg-pulse/15 blur-[110px] animate-aurora [animation-delay:-7s]" />
          <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(16,24,40,0.025)_1px,transparent_1px),linear-gradient(to_bottom,rgba(16,24,40,0.025)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_72%)]" />
        </div>
        <div className="relative mx-auto max-w-6xl px-5 pb-16 pt-16 lg:pt-24">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            {/* copy */}
            <div className="text-center lg:text-left">
              <Link
                href="/product"
                className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface/80 px-3 py-1 text-xs font-medium text-muted shadow-sm backdrop-blur transition hover:border-accent/40"
              >
                <Sparkles className="h-3.5 w-3.5 text-accent" /> AI security + compliance, human-in-the-loop
              </Link>

              <h1 className="mx-auto mt-6 max-w-xl text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl lg:mx-0 lg:text-6xl">
                Enterprise deals stall on security.{" "}
                <span className="text-accent">Stop losing them.</span>
              </h1>
              <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted lg:mx-0">
                The questionnaire, the SOC 2, the pentest your biggest customer is asking for — TensorShield handles it.
                An AI security engineer finds and fixes it, an AI pentester proves it by exploitation, and a named human
                signs the calls that matter — across code, cloud, and identity. No security hire required.
              </p>

              <div className="mt-8 flex flex-wrap items-center justify-center gap-3 lg:justify-start">
                <Link
                  href="/signup"
                  className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
                >
                  Start free <ArrowRight className="h-4 w-4" />
                </Link>
                <Link
                  href="/product"
                  className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong"
                >
                  See how it works
                </Link>
              </div>
              <p className="mt-4 text-xs text-faint">SOC 2 · ISO 27001 · GDPR · HIPAA · +18 more · No credit card to start</p>
              <Link href="/scan" className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline">
                Or check if your domain is spoofable — free, no signup <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>

            {/* live product preview */}
            <div className="animate-fade-rise">
              <LiveConsole />
            </div>
          </div>

          <StackPipeline />
        </div>
      </section>

      {/* Trust signals — who built it, what it runs on, how it's built, who it's for */}
      <TrustBar />

      {/* The architecture, made legible — a free substrate + the two AI teammates + a human who signs.
          (Was a black box; the AI Pentester was absent above the fold.) */}
      <ArchStack />

      {/* The interaction model — one-click agentic actions (auto-fix, launch a pentest…), not a chat box. */}
      <AgenticActions />

      {/* USP #1 — we prioritize the alerts so you don't have to (noise-reduction funnel) */}
      <Prioritize />

      {/* USP #2 / Differentiator — we go from alert to fix, not just flag (vs advise-only tools) */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <Reveal className="mx-auto mb-10 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">The difference</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              Most tools stop at the finding. TensorShield ships the fix.
            </h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              A dashboard full of risks is still your problem to solve. TensorShield prepares the actual remediation —
              and applies it the moment you approve.
            </p>
          </Reveal>
          <Reveal delay={90} className="grid gap-4 sm:grid-cols-2">
            <div className="card p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-muted">
                <XCircle className="h-4 w-4 text-faint" /> Advise-only tools
              </div>
              <ul className="mt-4 space-y-2.5 text-sm text-muted">
                {["Hand you a list of risks", "“Remediation guidance” you implement yourself", "You still need an engineer to act", "Evidence you assemble by hand"].map((x) => (
                  <li key={x} className="flex items-start gap-2.5">
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-faint" /> {x}
                  </li>
                ))}
              </ul>
            </div>
            <div className="card border-accent/40 bg-accent-soft/30 p-6">
              <div className="flex items-center gap-2 text-sm font-semibold text-accent">
                <Wrench className="h-4 w-4" /> TensorShield
              </div>
              <ul className="mt-4 space-y-2.5 text-sm text-ink">
                {["Opens the pull request with the fix", "Applies the cloud / identity change on approval", "Auto-handles the low-risk work; gates the rest", "Signs the evidence pack automatically"].map((x) => (
                  <li key={x} className="flex items-start gap-2.5">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
                  </li>
                ))}
              </ul>
            </div>
          </Reveal>

          {/* From alert to fixed — USP #2 made tangible: the concrete remediation path, animated */}
          <Reveal delay={150} className="mt-8 rounded-2xl border border-border bg-bg p-4 sm:p-5">
            <div className="mb-4 text-center text-[11px] font-semibold uppercase tracking-wider text-faint">
              From alert to fixed — automatically, with you approving what matters
            </div>
            <div className="flex min-w-max items-stretch gap-1.5 overflow-x-auto sm:min-w-0 sm:justify-center [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
              {[
                { icon: ScanLine, t: "Detected", d: "ranked, deduped" },
                { icon: Wrench, t: "Fix prepared", d: "PR · config · runbook" },
                { icon: CheckCircle2, t: "You approve", d: "1 tap, tier-gated" },
                { icon: GitBranch, t: "Applied", d: "via your connector" },
                { icon: ShieldCheck, t: "Re-verified", d: "confirmed gone" },
              ].map(({ icon: Icon, t, d }, i, arr) => (
                <div key={t} className="flex items-stretch gap-1.5">
                  <div className="w-[8.2rem] shrink-0 rounded-xl border border-border bg-surface p-3 text-center shadow-card">
                    <span className="mx-auto grid h-8 w-8 place-items-center rounded-lg bg-accent-soft text-accent">
                      <Icon className="h-4 w-4" />
                    </span>
                    <div className="mt-2 text-xs font-semibold text-ink">{t}</div>
                    <div className="mt-0.5 text-[11px] leading-snug text-muted">{d}</div>
                  </div>
                  {i < arr.length - 1 && (
                    <div className="flex w-6 shrink-0 items-center self-center">
                      <div className="relative h-px w-full bg-gradient-to-r from-border via-accent/40 to-border">
                        <span
                          className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_8px_rgba(79,70,229,0.6)] animate-flow-x"
                          style={{ animationDelay: `${i * 0.45}s` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      {/* Social proof / stats */}
      <section className="border-y border-border bg-surface">
        <Reveal className="mx-auto grid max-w-5xl grid-cols-2 gap-6 px-5 py-10 text-center sm:grid-cols-4">
          {[
            ["22", "compliance frameworks"],
            ["30+", "OSS scanners wrapped"],
            ["24/7", "autonomous monitoring"],
            ["1-tap", "approval, fully signed"],
          ].map(([n, l]) => (
            <div key={l}>
              <div className="text-3xl font-semibold tracking-tight text-ink">{n}</div>
              <div className="mt-1 text-xs text-muted">{l}</div>
            </div>
          ))}
        </Reveal>
      </section>

      {/* Two ways to engage — the two-sided GTM (bring your own expert, or use ours) */}
      <EngageModels />

      {/* How it works */}
      <Section eyebrow="How it works" title="Set up once. It runs itself." sub="Connect a system and the agent takes it from there — you stay in control of anything risky.">
        <div className="grid gap-5 md:grid-cols-3">
          {[
            { icon: Plug, step: "1", t: "Connect", d: "GitHub, AWS, Google Workspace, Okta — one click of OAuth. The agent discovers what to watch." },
            { icon: ScanLine, step: "2", t: "The agent works", d: "It scans continuously, triages real risk from noise, and prepares the fix — patches, configs, tickets." },
            { icon: CheckCircle2, step: "3", t: "You approve", d: "Anything consequential waits for one tap of your approval. Everything is signed and auditable." },
          ].map(({ icon: Icon, step, t, d }) => (
            <div key={t} className="card p-6">
              <div className="flex items-center gap-3">
                <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent-soft text-accent">
                  <Icon className="h-5 w-5" />
                </span>
                <span className="text-xs font-semibold text-faint">STEP {step}</span>
              </div>
              <h3 className="mt-4 text-lg font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Platform overview — the whole product in one view: the five surfaces + the HITL spine */}
      <PlatformOverview />

      {/* Unified platform — every product + asset feeds one finding graph (better detection + compliance) */}
      <UnifiedPlatform />

      {/* Compare — the category wedge */}
      <Compare />

      {/* Trust / signed evidence */}
      <section className="bg-surface">
        <div className="mx-auto grid max-w-6xl items-center gap-10 px-5 py-20 lg:grid-cols-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Built on trust</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              Evidence you can prove — not screenshots you hope hold up.
            </h2>
            <p className="mt-4 text-base leading-relaxed text-muted">
              Every finding cites the tool that backs it, and every compliance artifact is signed and pinned to the exact
              state it was assessed against. An auditor can re-run the proof. Your customers can trust the badge.
            </p>
            <ul className="mt-6 space-y-3">
              {[
                "ed25519-signed, tamper-evident evidence packs",
                "Grounded findings — the agent never asserts what a tool didn't prove",
                "A signed decision ledger for every automated and human action",
              ].map((x) => (
                <li key={x} className="flex items-start gap-2.5 text-sm text-ink">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-pulse" /> {x}
                </li>
              ))}
            </ul>
            <Link href="/security" className="mt-7 inline-flex items-center gap-1.5 text-sm font-semibold text-accent hover:underline">
              How we keep you safe <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          <ConnectorsVisual />
        </div>
      </section>

      {/* CTA band */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Give your startup a security team today.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect your first system in minutes. See your posture, your compliance gaps, and your first fixes — for free.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/pricing" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              See pricing
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}

// Compare — the category wedge. SMB buyers are choosing between a compliance platform, a
// point scanner, and hiring. We're the one box that does all three, autonomously. Honest
// category comparison (capabilities vary by vendor/plan — footnoted), no fabricated metrics.
function Compare() {
  const cols = [
    { name: "TensorShield", sub: "the autonomous team", highlight: true },
    { name: "Compliance platforms", sub: "Vanta · Drata", highlight: false },
    { name: "Point scanners", sub: "Snyk · Dependabot", highlight: false },
    { name: "Hire an engineer", sub: "$150k+/yr", highlight: false },
  ];
  // cell value: "yes" | "no" | "part" | a literal string (rendered as text)
  const rows: { label: string; cells: (string)[] }[] = [
    { label: "Deep detection — code, cloud, web, identity", cells: ["yes", "part", "part", "yes"] },
    { label: "Ships the actual fix (PR / config change)", cells: ["yes", "no", "no", "yes"] },
    { label: "Compliance evidence — 22 frameworks, signed", cells: ["yes", "yes", "no", "part"] },
    { label: "Identity & email-spoofing posture", cells: ["yes", "part", "no", "yes"] },
    { label: "Runs 24/7, autonomous, human-gated", cells: ["yes", "no", "no", "no"] },
    { label: "Cost for an SMB", cells: ["$/mo", "$$/mo", "$/mo", "$$$$/yr"] },
  ];
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <div className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why TensorShield</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
          One platform where you&apos;d otherwise stitch three — or hire.
        </h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          Most SMBs end up paying for a compliance tool, a scanner, and the engineer to run both. TensorShield is the one
          box that detects, fixes, and proves — with you approving anything that matters.
        </p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-separate border-spacing-0 text-sm">
          <thead>
            <tr>
              <th className="w-[34%] p-0" />
              {cols.map((c) => (
                <th
                  key={c.name}
                  className={`rounded-t-xl px-4 py-3 text-center align-bottom ${c.highlight ? "bg-accent-soft/60 ring-1 ring-accent/30" : ""}`}
                >
                  <div className={`text-sm font-semibold ${c.highlight ? "text-accent" : "text-ink"}`}>{c.name}</div>
                  <div className="mt-0.5 text-[11px] font-normal text-faint">{c.sub}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, ri) => (
              <tr key={r.label}>
                <td className="border-t border-border py-3 pr-4 text-sm text-ink">{r.label}</td>
                {r.cells.map((v, ci) => (
                  <td
                    key={ci}
                    className={`border-t border-border px-4 py-3 text-center ${
                      cols[ci].highlight ? "bg-accent-soft/30" : ""
                    } ${ri === rows.length - 1 ? "rounded-b-xl" : ""}`}
                  >
                    <CompareCell v={v} highlight={cols[ci].highlight} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 text-center text-[11px] text-faint">
        Category comparison — capabilities vary by vendor and plan. Vanta &amp; Drata are compliance-automation platforms;
        Snyk &amp; Dependabot are code/dependency scanners.
      </p>

      {/* ROI band */}
      <div className="mt-10 flex flex-col items-center gap-4 rounded-2xl border border-accent/30 bg-accent-soft/30 px-6 py-8 text-center sm:flex-row sm:text-left">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
          <Wallet className="h-6 w-6" />
        </span>
        <div className="flex-1">
          <div className="text-lg font-semibold tracking-tight">A fraction of a hire — that never sleeps, takes PTO, or quits.</div>
          <p className="mt-1 text-sm leading-relaxed text-muted">
            A mid-level security engineer runs $150k+/yr and can&apos;t cover detection, compliance, and identity alone.
            TensorShield does all three continuously, and only pulls in a human for the calls that need judgment.
          </p>
        </div>
        <Link
          href="/pricing"
          className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
        >
          See pricing <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </section>
  );
}

function CompareCell({ v, highlight }: { v: string; highlight: boolean }) {
  if (v === "yes") return <CheckCircle2 className={`mx-auto h-5 w-5 ${highlight ? "text-pulse" : "text-pulse/80"}`} />;
  if (v === "no") return <XCircle className="mx-auto h-5 w-5 text-faint/60" />;
  if (v === "part") return <Minus className="mx-auto h-5 w-5 text-amber-500/70" />;
  // literal text (e.g. cost)
  return <span className={`text-sm font-semibold ${highlight ? "text-accent" : "text-muted"}`}>{v}</span>;
}

function Section({ eyebrow, title, sub, children }: { eyebrow: string; title: string; sub: string; children: React.ReactNode }) {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <Reveal className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">{eyebrow}</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">{title}</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">{sub}</p>
      </Reveal>
      <Reveal delay={90}>{children}</Reveal>
    </section>
  );
}

// The hero pipeline: your stack → TensorShield → outcomes. Communicates the value prop at
// a glance — and leads with the wedge (we ship fixes, not just findings).
function StackPipeline() {
  const stack = [
    { icon: Cloud, label: "Cloud", sub: "AWS · GCP · Azure" },
    { icon: Mail, label: "Workspace", sub: "Google · M365" },
    { icon: GitBranch, label: "Code", sub: "GitHub · GitLab" },
    { icon: KeyRound, label: "Identity & MFA", sub: "Okta · SSO" },
  ];
  const outcomes = [
    { icon: Wrench, label: "Fixes shipped", sub: "PRs & configs, gated", strong: true },
    { icon: FileCheck2, label: "22 frameworks mapped", sub: "SOC 2 · ISO · GDPR · +19" },
    { icon: Lock, label: "Signed evidence pack", sub: "reproducible, not screenshots" },
    { icon: ClipboardCheck, label: "Auditor-ready report", sub: "PDF · Markdown · CSV" },
    { icon: Activity, label: "Live posture dashboard", sub: "continuous, 24/7" },
  ];
  return (
    <div className="mx-auto mt-16 max-w-5xl">
      <div className="card grid items-stretch gap-4 p-5 shadow-elevated md:grid-cols-[1fr_auto_1fr_auto_1.15fr] md:gap-2 md:p-6">
        {/* Your stack */}
        <Column heading="Your stack">
          {stack.map(({ icon: Icon, label, sub }) => (
            <Node key={label} Icon={Icon} label={label} sub={sub} />
          ))}
        </Column>

        <Connector />

        {/* TensorShield — the live core: a breathing glow + a pulsing ring around the shield */}
        <div className="flex items-center">
          <div className="w-full rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 text-center animate-glow-pulse">
            <span className="relative mx-auto grid h-11 w-11 place-items-center rounded-xl bg-accent text-white shadow-sm">
              <span className="absolute inset-0 rounded-xl bg-accent/40 animate-ping" />
              <ShieldCheck className="relative h-5 w-5" />
            </span>
            <div className="mt-3 text-base font-semibold">TensorShield</div>
            <div className="mt-1 text-xs font-medium text-accent">Detect · Triage · Fix · Prove</div>
            <div className="mt-2 text-[11px] leading-relaxed text-muted">automated, with a human in the loop</div>
          </div>
        </div>

        <Connector delay={1.3} />

        {/* Outcomes */}
        <Column heading="What you get">
          {outcomes.map(({ icon: Icon, label, sub, strong }) => (
            <Node key={label} Icon={Icon} label={label} sub={sub} strong={strong} />
          ))}
        </Column>
      </div>
      <p className="mt-4 text-center text-xs text-faint">
        Read-only by default · write-back only on your approval · per-tenant isolation · ed25519-signed evidence
      </p>
    </div>
  );
}

function Column({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col">
      <div className="mb-2 text-center text-[10px] font-semibold uppercase tracking-wider text-faint md:text-left">{heading}</div>
      <div className="flex flex-1 flex-col gap-2">{children}</div>
    </div>
  );
}

function Node({ Icon, label, sub, strong }: { Icon: typeof Cloud; label: string; sub: string; strong?: boolean }) {
  return (
    <div
      className={`flex items-center gap-2.5 rounded-xl border px-3 py-2 text-left ${
        strong ? "border-accent/40 bg-accent-soft/40" : "border-border bg-surface"
      }`}
    >
      <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${strong ? "bg-accent text-white" : "bg-surface-2 text-muted"}`}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <span className="min-w-0">
        <span className={`block truncate text-xs font-semibold ${strong ? "text-accent" : "text-ink"}`}>{label}</span>
        <span className="block truncate text-[10px] text-faint">{sub}</span>
      </span>
    </div>
  );
}

// Live connector between columns — a highlight dot streams left→right along the track on desktop
// (data flowing into the agent and back out as fixes); a down-chevron on mobile. The `delay`
// staggers the two connectors so the pulse appears to travel through TensorShield.
function Connector({ delay = 0 }: { delay?: number }) {
  return (
    <div className="flex items-center justify-center text-faint">
      <div className="relative hidden h-px w-10 overflow-visible bg-gradient-to-r from-border via-accent/40 to-border md:block">
        <span
          className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_8px_rgba(79,70,229,0.7)] animate-flow-x"
          style={{ animationDelay: `${delay}s` }}
        />
      </div>
      <ChevronDown className="h-5 w-5 md:hidden" />
    </div>
  );
}

// The "connects to everything" visual for the trust section.
function ConnectorsVisual() {
  const items: { icon?: typeof FileCheck2; brand?: string; label: string }[] = [
    { brand: "github", label: "GitHub" },
    { brand: "aws", label: "AWS" },
    { brand: "okta", label: "Okta" },
    { icon: FileCheck2, label: "SOC 2" },
    { icon: Lock, label: "Signed" },
    { icon: Star, label: "Trust" },
  ];
  return (
    <div className="card relative grid grid-cols-3 gap-3 p-6">
      {items.map(({ icon: Icon, brand, label }) => (
        <div key={label} className="flex flex-col items-center gap-2 rounded-xl border border-border bg-bg py-5 text-center">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-surface text-ink shadow-sm">
            {brand ? <ProviderIcon kind={brand} className="h-4 w-4" /> : Icon ? <Icon className="h-4 w-4" /> : null}
          </span>
          <span className="text-[11px] font-medium text-muted">{label}</span>
        </div>
      ))}
    </div>
  );
}
