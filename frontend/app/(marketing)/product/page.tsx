import Link from "next/link";
import { pageMeta } from "@/lib/seo";
import {
  Plug, ScanLine, Filter, Wrench, CheckCircle2, FileCheck2, ArrowRight,
  Building2, Wallet, Code2, ClipboardCheck, Bot, UserCheck,
  Globe, Webhook, Box, Cloud, Smartphone, Network, Radar, KeyRound,
} from "lucide-react";
import { FRAMEWORKS, FRAMEWORK_LABEL, FRAMEWORK_CATEGORY } from "@/lib/frameworks";
import { ASSET_SURFACES } from "@/lib/assets";

export const metadata = pageMeta({
  title: "Product — how TensorShield works",
  description: "Connect a system and a fractional security team goes to work: detect across every surface, prove what's exploitable with a captured PoC, fix it, and prove your compliance — with you in the loop where it matters.",
  path: "/product",
});

const LOOP = [
  { icon: Plug, t: "Connect", d: "OAuth into GitHub, AWS, Google Workspace, M365, or Okta. The agent discovers your assets — repos, accounts, identities — and starts immediately." },
  { icon: ScanLine, t: "Detect", d: "It runs the leading open-source scanners across every surface continuously, so coverage matches what a standalone security tool would find." },
  { icon: Filter, t: "Triage & prove", d: "An AI security engineer separates real, exploitable risk from scanner noise — and, where you authorize active testing, proves the exploit with a captured proof-of-concept. A finding is confirmed, not just flagged." },
  { icon: Wrench, t: "Fix", d: "It prepares the actual remediation — a pull request, a config change, an identity action, or a ticket — ready to ship." },
  { icon: UserCheck, t: "Approve", d: "Low-risk fixes apply automatically; anything consequential waits for one tap of your approval. Autonomy where it's earned." },
  { icon: FileCheck2, t: "Prove", d: "Every finding maps to controls across 14 frameworks and lands in a signed, auditor-ready evidence pack — automatically." },
];

const PERSONAS = [
  { icon: Building2, who: "Founders & owners", v: "One glance tells you if you're safe and compliant — and the agent is already handling the rest." },
  { icon: Wallet, who: "Ops & IT", v: "Connect tools, approve fixes from a keyboard-fast inbox, and show real progress — no security background needed." },
  { icon: Code2, who: "Developers", v: "Get actionable fixes as PRs and tickets in the tools you already use, with the evidence attached." },
  { icon: ClipboardCheck, who: "Compliance & auditors", v: "Live control posture, signed evidence, and auto-answered questionnaires — reproducible, not screenshots." },
];

export default function Product() {
  return (
    <>
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-10 pt-20 text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">The product</span>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">A security team in a loop, not a tool in a tab.</h1>
          <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
            Connect a system once. TensorShield runs the whole loop — detect, triage, fix, and prove — and pulls you in
            only where human judgment matters.
          </p>
        </div>
      </section>

      {/* The loop */}
      <section className="mx-auto max-w-5xl px-5 pb-12">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
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

      {/* Two layers */}
      <section className="bg-surface">
        <div className="mx-auto grid max-w-6xl items-center gap-10 px-5 py-20 lg:grid-cols-2">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Under the hood</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Best-in-class detection, plus an AI engineer to make sense of it.</h2>
            <p className="mt-4 text-base leading-relaxed text-muted">
              Most tools give you a scanner and a 400-row report. TensorShield pairs a complete detection layer with an AI
              security engineer that triages, chains, and explains — turning raw findings into decisions a non-expert
              can act on.
            </p>
            <ul className="mt-6 space-y-3 text-sm text-ink">
              {[
                ["Detection layer", "Wraps the leading OSS scanners — recall on par with running each tool yourself, across every asset you run."],
                ["AI security engineer", "Verifies what's real, chains issues into attack paths, writes the fix and the plain-English why."],
                ["Human in the loop", "Tier-gated approvals on anything consequential, every decision signed into a tamper-evident ledger."],
              ].map(([h, d]) => (
                <li key={h} className="flex items-start gap-3">
                  <Bot className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                  <span><span className="font-semibold">{h}.</span> <span className="text-muted">{d}</span></span>
                </li>
              ))}
            </ul>
          </div>
          <div className="card space-y-3 p-6">
            {[
              ["L1 · Detection", "katana · nuclei · semgrep · trivy · prowler · gitleaks …", "text-ink"],
              ["L1.5 · Enrichment", "false-positive filter · threat intel (KEV/EPSS) · compliance mapping", "text-muted"],
              ["L2 · AI engineer", "triage · chain · verify · remediate · explain", "text-accent"],
              ["HITL · The gate", "you approve · signed ledger", "text-pulse"],
            ].map(([h, d, c]) => (
              <div key={h} className="rounded-xl border border-border bg-bg p-4">
                <div className={`text-sm font-semibold ${c}`}>{h}</div>
                <div className="mono mt-1 text-[11px] text-faint">{d}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Asset coverage */}
      <AssetCoverageBand />

      {/* Compliance coverage */}
      <ComplianceBand />

      {/* Personas */}
      <section className="mx-auto max-w-6xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Built for your whole team</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">Everyone gets what they need.</h2>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {PERSONAS.map(({ icon: Icon, who, v }) => (
            <div key={who} className="card p-5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3.5 text-sm font-semibold">{who}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{v}</p>
            </div>
          ))}
        </div>
      </section>

      <CTABand />
    </>
  );
}

// ComplianceBand — surfaces the 14-framework breadth on the deep product page (it was the
// one marketing page that omitted it). Grouped by category, sourced from the shared
// framework list so it never drifts from what the app actually maps.
const CATEGORY_ORDER = ["Security & trust", "Sector & payments", "Privacy", "Government"];

function ComplianceBand() {
  const groups = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: FRAMEWORKS.filter((f) => FRAMEWORK_CATEGORY[f] === cat),
  })).filter((g) => g.items.length > 0);

  return (
    <section className="bg-surface">
      <div className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Prove it — automatically</span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight">{FRAMEWORKS.length} frameworks, mapped as findings land.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            Every finding maps to the controls it touches — no spreadsheet, no screenshots. Your evidence pack stays
            current and signed, ready for an auditor or a customer&apos;s security review.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {groups.map((g) => (
            <div key={g.cat} className="card p-5">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">{g.cat}</div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {g.items.map((f) => (
                  <span key={f} className="inline-flex items-center gap-1 rounded-full border border-border bg-bg px-2.5 py-1 text-xs font-medium text-ink">
                    <CheckCircle2 className="h-3 w-3 text-pulse" /> {FRAMEWORK_LABEL[f] ?? f}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// AssetCoverageBand — the buyer-facing "what we scan" matrix. Single-sourced
// from lib/assets.ts so it never drifts from the engine's real asset coverage.
const SURFACE_ICON: Record<string, typeof Globe> = {
  web_application: Globe,
  api: Webhook,
  repository: Code2,
  container_image: Box,
  cloud_account: Cloud,
  mobile_application: Smartphone,
  ip_address: Network,
  domain: Radar,
  workspace: KeyRound,
};

function AssetCoverageBand() {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <div className="mx-auto mb-12 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">Everything you run</span>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight">One agent across your whole attack surface.</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          Code, cloud, web, APIs, containers, mobile, network, and identity — each assessed by the leading open-source
          scanner for that surface, continuously.
        </p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {ASSET_SURFACES.map((s) => {
          const Icon = SURFACE_ICON[s.key] ?? Globe;
          return (
            <div key={s.key} className="card p-5">
              <div className="flex items-center gap-2.5">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <h3 className="text-sm font-semibold">{s.label}</h3>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-muted">{s.scans}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {s.tools.map((t) => (
                  <span key={t} className="mono inline-flex items-center rounded-md border border-border bg-bg px-2 py-0.5 text-[11px] text-faint">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function CTABand() {
  return (
    <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
      <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
      <div className="relative mx-auto max-w-2xl px-5 py-16 text-center text-white">
        <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">See it run on your own systems.</h2>
        <p className="mx-auto mt-3 max-w-md text-white/75">Connect one system free and watch the loop work in minutes.</p>
        <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
          <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
            Start free <ArrowRight className="h-4 w-4" />
          </Link>
          <Link href="/pricing" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
            See pricing
          </Link>
        </div>
      </div>
    </section>
  );
}
