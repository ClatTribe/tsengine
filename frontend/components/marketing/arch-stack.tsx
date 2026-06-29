import Link from "next/link";
import { Bot, Crosshair, UserCheck, Layers, ArrowRight } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// The product architecture made legible (the framework — docs/product-framework.md), so the homepage
// shows the structure instead of a black box: a FREE deterministic L1.7 substrate that BOTH AI teammates
// reason over — AI Security Engineer (defense) + AI Pentester (attack) — with a named human accountable
// on top. Rendered top-down (human → two teammates → substrate); each layer links to its page. Closes the
// audit gap "the AI Pentester is absent from the homepage / the architecture is a black box".
export function ArchStack() {
  return (
    <section className="mx-auto max-w-5xl px-5 py-20">
      <Reveal className="mx-auto mb-10 max-w-2xl text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Free scanning. Two AI agents. A human who signs.</h2>
        <p className="mt-3 text-base leading-relaxed text-muted">
          Not a black box. A deterministic + ML-based security &amp; compliance scanning engine you can see — then an
          AI security engineer and an AI pentester that reason over it, with a named human accountable for the calls that matter.
        </p>
      </Reveal>

      <Reveal delay={80} className="space-y-3">
        {/* Top — the named human (HITL). */}
        <LayerCard
          href="/product"
          icon={UserCheck}
          tone="human"
          kicker="The human in the loop"
          title="A named person signs the calls that matter"
          desc="Risk acceptance, audit attestation, pentest sign-off, policy publish — the agent proposes, a named human disposes. Every decision signed to a tamper-evident ledger."
        />

        {/* Middle — the two AI personas, co-equal, side by side. */}
        <div className="grid gap-3 sm:grid-cols-2">
          <LayerCard
            href="/ai-security-engineer"
            icon={Bot}
            tone="ai"
            kicker="AI Security Engineer · defense"
            title="Prioritizes, chains, fixes, explains"
            desc="Reasons over the whole estate — what's exploitable, how it chains to a crown jewel, what to fix first — and writes the fix in plain English."
          />
          <LayerCard
            href="/ai-pentest"
            icon={Crosshair}
            tone="ai"
            kicker="AI Pentester · attack"
            title="Proves it — exploitation, not theory"
            desc="A long-horizon agent that actually exploits the finding (benign, rules-of-engagement-gated) and upgrades it to verified with a captured PoC — the no-false-positive bar."
          />
        </div>

        {/* Base — the free deterministic substrate everything stands on. */}
        <LayerCard
          href="/cross-detection"
          icon={Layers}
          tone="substrate"
          kicker="Deterministic + ML scanning · free"
          title="30+ OSS scanners, correlated"
          desc="Best-in-class open-source detection across code · cloud · attack surface · identity, plus cross-surface correlation, threat-intel (KEV/EPSS), and compliance mapping. The security-engineer + auditor deliverable — free."
        />
      </Reveal>
    </section>
  );
}

function LayerCard({
  href, icon: Icon, kicker, title, desc, tone,
}: {
  href: string;
  icon: typeof Bot;
  kicker: string;
  title: string;
  desc: string;
  tone: "human" | "ai" | "substrate";
}) {
  const toneRing =
    tone === "human"
      ? "border-accent/40 bg-accent-soft/30"
      : tone === "substrate"
        ? "border-border bg-surface-2/50"
        : "border-border bg-surface";
  return (
    <Link href={href} className={`group flex items-start gap-4 rounded-2xl border p-5 shadow-card transition hover:-translate-y-0.5 hover:border-accent/50 ${toneRing}`}>
      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
        <Icon className="h-5 w-5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-accent">{kicker}</div>
        <div className="mt-0.5 text-sm font-semibold text-ink">{title}</div>
        <p className="mt-1 text-xs leading-relaxed text-muted">{desc}</p>
      </div>
      <ArrowRight className="mt-1 hidden h-4 w-4 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent sm:block" />
    </Link>
  );
}
