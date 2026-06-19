import Link from "next/link";
import {
  ShieldCheck, Sparkles, ArrowRight, Plug, ScanLine, CheckCircle2, Bug, FileCheck2,
  UserCheck, Lock, Radar, Github, Cloud, KeyRound, Star,
} from "lucide-react";

export const metadata = {
  title: "Sentinel — your fractional security team",
  description:
    "AI security + compliance for SMBs. Sentinel finds, triages, and fixes — with a human in the loop where it matters. No security hire required.",
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
            Sentinel continuously finds, triages, and fixes security &amp; compliance issues across your code,
            cloud, and identity — and pulls you in only where judgment is needed. No security hire required.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/login"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover"
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

          <HeroPreview />
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
            <Link href="/login" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
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

// A stylized product preview under the hero — the posture dashboard, light.
function HeroPreview() {
  return (
    <div className="mx-auto mt-14 max-w-4xl">
      <div className="rounded-2xl border border-border bg-surface p-2 shadow-elevated">
        <div className="rounded-xl bg-bg p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-white">
                <ShieldCheck className="h-4 w-4" />
              </span>
              <div className="text-left">
                <div className="text-sm font-semibold leading-none">Posture</div>
                <div className="mt-1 text-[11px] text-faint">Demo Corp · live</div>
              </div>
            </div>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-pulse-soft px-2.5 py-1 text-xs font-medium text-pulse">
              <span className="pulse-dot" /> Protected
            </span>
          </div>
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Risk", "Low", "text-pulse"],
              ["Open issues", "2", "text-medium"],
              ["SOC 2", "94%", "text-ink"],
              ["Fixes queued", "1", "text-accent"],
            ].map(([l, v, c]) => (
              <div key={l} className="rounded-xl border border-border bg-surface p-3.5 text-left">
                <div className={`text-2xl font-semibold ${c}`}>{v}</div>
                <div className="mt-0.5 text-[11px] text-muted">{l}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 rounded-xl border border-border bg-surface p-3.5 text-left">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wide text-faint">Agent activity</div>
            {[
              ["Scanned acme/api · 0 new criticals", "text-pulse"],
              ["Prepared fix: enforce MFA for 1 admin — awaiting you", "text-accent"],
              ["Resolved: open S3 bucket", "text-muted"],
            ].map(([t, c], i) => (
              <div key={i} className="flex items-center gap-2 py-1 text-xs">
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${c.replace("text-", "bg-")}`} />
                <span className="truncate text-muted">{t}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
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
