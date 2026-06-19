import Link from "next/link";
import {
  ShieldCheck, Sparkles, ArrowRight, Plug, ScanLine, CheckCircle2, Bug, FileCheck2,
  UserCheck, Lock, Radar, Github, Cloud, KeyRound, Star, Wrench, Mail, ClipboardCheck,
  Activity, ChevronDown, GitBranch, XCircle,
} from "lucide-react";

export const metadata = {
  title: "TensorShield — your fractional security team",
  description:
    "AI security + compliance for SMBs. TensorShield finds, triages, and fixes — with a human in the loop where it matters. No security hire required.",
};

export default function Landing() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-6xl px-5 pb-16 pt-20 text-center">
          <Link
            href="/product"
            className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm transition hover:border-accent/40"
          >
            <Sparkles className="h-3.5 w-3.5 text-accent" /> AI security + compliance, human-in-the-loop
          </Link>

          <h1 className="mx-auto mt-6 max-w-3xl text-4xl font-semibold leading-[1.08] tracking-tight sm:text-6xl">
            Your fractional security team,{" "}
            <span className="text-accent">running while you build.</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            TensorShield continuously finds, triages, and fixes security &amp; compliance issues across your code,
            cloud, and identity — and pulls you in only where judgment is needed. No security hire required.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
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
          <p className="mt-4 text-xs text-faint">SOC 2 · ISO 27001 · PCI-DSS · HIPAA · No credit card to start</p>

          <StackPipeline />
        </div>
      </section>

      {/* Differentiator — we fix, not just flag (vs advise-only tools) */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <div className="mx-auto mb-10 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">The difference</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              Most tools stop at the finding. TensorShield ships the fix.
            </h2>
            <p className="mt-3 text-base leading-relaxed text-muted">
              A dashboard full of risks is still your problem to solve. TensorShield prepares the actual remediation —
              and applies it the moment you approve.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
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
          </div>
        </div>
      </section>

      {/* Social proof / stats */}
      <section className="border-y border-border bg-surface">
        <div className="mx-auto grid max-w-5xl grid-cols-2 gap-6 px-5 py-10 text-center sm:grid-cols-4">
          {[
            ["6", "systems connect in minutes"],
            ["24/7", "autonomous monitoring"],
            ["80%+", "fixes auto-prepared"],
            ["6", "frameworks mapped"],
          ].map(([n, l]) => (
            <div key={l}>
              <div className="text-3xl font-semibold tracking-tight text-ink">{n}</div>
              <div className="mt-1 text-xs text-muted">{l}</div>
            </div>
          ))}
        </div>
      </section>

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

      {/* Features */}
      <Section eyebrow="One platform" title="Security and compliance, handled." sub="The work a security engineer and a compliance manager would do — automated, on one auditable loop.">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { icon: Bug, t: "Best-in-class detection", d: "Wraps the leading OSS scanners across web, APIs, code, containers, cloud & identity — recall on par with standalone tools." },
            { icon: FileCheck2, t: "Compliance on autopilot", d: "Findings map to SOC 2 / ISO / PCI / HIPAA controls automatically, with a signed evidence pack and an auto-answered questionnaire." },
            { icon: Radar, t: "Continuous monitoring", d: "Re-scans on every change and on a schedule — new high-severity issues page on-call, resolved ones close themselves." },
            { icon: UserCheck, t: "Human in the loop", d: "The agent proposes; you approve. Tier-gated, signed into a tamper-evident ledger — autonomy where it's earned." },
            { icon: KeyRound, t: "Identity posture", d: "MFA gaps, risky OAuth grants, stale accounts, email spoofing (DMARC/SPF/DKIM) — fixed across Google, M365 & Okta." },
            { icon: Lock, t: "Provable evidence", d: "Every claim is backed by a tool and ed25519-signed. Auditors get reproducible proof, not screenshots." },
          ].map(({ icon: Icon, t, d }) => (
            <div key={t} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </Section>

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

function Section({ eyebrow, title, sub, children }: { eyebrow: string; title: string; sub: string; children: React.ReactNode }) {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <div className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">{eyebrow}</span>
        <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">{title}</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">{sub}</p>
      </div>
      {children}
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
    { icon: FileCheck2, label: "6 frameworks mapped", sub: "SOC 2 · ISO · PCI · HIPAA" },
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

        {/* TensorShield */}
        <div className="flex items-center">
          <div className="w-full rounded-2xl border border-accent/40 bg-accent-soft/40 p-5 text-center">
            <span className="mx-auto grid h-11 w-11 place-items-center rounded-xl bg-accent text-white shadow-sm">
              <ShieldCheck className="h-5 w-5" />
            </span>
            <div className="mt-3 text-base font-semibold">TensorShield</div>
            <div className="mt-1 text-xs font-medium text-accent">Detect · Triage · Fix · Prove</div>
            <div className="mt-2 text-[11px] leading-relaxed text-muted">automated, with a human in the loop</div>
          </div>
        </div>

        <Connector />

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

// Arrow between columns — horizontal on desktop, down-chevron on mobile.
function Connector() {
  return (
    <div className="flex items-center justify-center text-faint">
      <ArrowRight className="hidden h-5 w-5 md:block" />
      <ChevronDown className="h-5 w-5 md:hidden" />
    </div>
  );
}

// The "connects to everything" visual for the trust section.
function ConnectorsVisual() {
  const items = [
    { icon: Github, label: "GitHub" },
    { icon: Cloud, label: "AWS" },
    { icon: KeyRound, label: "Okta" },
    { icon: FileCheck2, label: "SOC 2" },
    { icon: Lock, label: "Signed" },
    { icon: Star, label: "Trust" },
  ];
  return (
    <div className="card relative grid grid-cols-3 gap-3 p-6">
      {items.map(({ icon: Icon, label }) => (
        <div key={label} className="flex flex-col items-center gap-2 rounded-xl border border-border bg-bg py-5 text-center">
          <span className="grid h-9 w-9 place-items-center rounded-lg bg-surface text-ink shadow-sm">
            <Icon className="h-4 w-4" />
          </span>
          <span className="text-[11px] font-medium text-muted">{label}</span>
        </div>
      ))}
    </div>
  );
}
