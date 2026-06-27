import Link from "next/link";
import { GitBranch, Cloud, Crosshair, KeyRound, ClipboardCheck, UserCheck, ArrowRight } from "lucide-react";
import { Reveal } from "@/components/marketing/reveal";

// PlatformOverview — the "whole platform in one view": the five surfaces TensorShield covers,
// each with its real capabilities and the outcome it serves, then the human-in-the-loop spine
// that ties them together (our differentiator). Capabilities are grounded in shipped features
// (§10 — nothing aspirational here).
const SURFACES = [
  {
    name: "Code",
    outcome: "Security",
    href: "/code-security",
    icon: GitBranch,
    blurb: "Every commit, dependency and pipeline.",
    caps: ["SAST", "Open-source (SCA)", "Secrets", "IaC misconfig", "Containers", "Supply-chain malware", "AI autofix + PR review"],
  },
  {
    name: "Cloud",
    outcome: "Security",
    href: "/cloud-security",
    icon: Cloud,
    blurb: "AWS · GCP · Azure, agentless.",
    caps: ["CSPM misconfig", "Attack-path mapping", "Data exposure (DSPM)", "Workload scan (CWPP)", "Search your cloud", "Drift detection"],
  },
  {
    name: "Attack",
    outcome: "Security",
    href: "/ai-pentest",
    icon: Crosshair,
    blurb: "Think like an attacker — and prove it.",
    caps: ["Autonomous AI pentest", "Authenticated DAST", "API discovery + fuzzing", "BOLA / BFLA authz", "Exploitation-proven"],
  },
  {
    name: "Identity",
    outcome: "Security",
    href: "/identity",
    icon: KeyRound,
    blurb: "Google · Microsoft 365 · Okta.",
    caps: ["MFA & SSO gaps", "Risky OAuth grants", "Stale / over-privileged", "SaaS posture (SSPM)", "Email auth (DMARC)"],
  },
  {
    name: "Compliance",
    outcome: "Compliance",
    href: "/frameworks",
    icon: ClipboardCheck,
    blurb: "Findings become audit-ready evidence.",
    caps: ["22 frameworks", "Auto control mapping", "Signed evidence packs", "Questionnaire autofill", "SOC 2 · ISO · GDPR · PCI · HIPAA"],
  },
];

export function PlatformOverview() {
  return (
    <section className="mx-auto max-w-6xl px-5 py-20">
      <Reveal className="text-center">
        <span className="text-xs font-semibold uppercase tracking-wider text-accent">The platform</span>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
          Everything a security &amp; compliance team does — one platform
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-base leading-relaxed text-muted">
          Five surfaces, one finding graph. Each runs the best open-source scanners, enriched by the AI
          engineer — feeding the two outcomes you actually buy: <span className="font-medium text-ink">security</span> and{" "}
          <span className="font-medium text-ink">compliance</span>.
        </p>
      </Reveal>

      <Reveal delay={80} className="mt-10 divide-y divide-border overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
        {SURFACES.map(({ name, outcome, href, icon: Icon, blurb, caps }) => (
          <Link
            key={name}
            href={href}
            className="group flex flex-col gap-3 p-5 transition hover:bg-surface-2/50 sm:flex-row sm:items-center sm:gap-5 sm:p-6"
          >
            {/* surface label */}
            <div className="flex items-center gap-3 sm:w-52 sm:shrink-0">
              <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-accent/10">
                <Icon className="h-5 w-5" />
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-base font-semibold text-ink">{name}</span>
                  <span
                    className={
                      outcome === "Compliance"
                        ? "rounded-full bg-pulse/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-pulse"
                        : "rounded-full bg-accent-soft px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent"
                    }
                  >
                    {outcome}
                  </span>
                </div>
                <span className="block text-xs leading-snug text-muted">{blurb}</span>
              </div>
            </div>

            {/* capability chips */}
            <div className="flex flex-wrap gap-1.5 sm:flex-1">
              {caps.map((c) => (
                <span key={c} className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-muted">
                  {c}
                </span>
              ))}
            </div>

            <ArrowRight className="hidden h-4 w-4 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-accent sm:block" />
          </Link>
        ))}
      </Reveal>

      {/* The HITL spine — the thread through all five surfaces (the differentiator vs flag-only tools). */}
      <Reveal delay={120} className="mt-4 flex items-start gap-3 rounded-2xl border border-accent/20 bg-accent-soft/40 p-5 sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
          <UserCheck className="h-5 w-5" />
        </span>
        <p className="text-sm leading-relaxed text-ink">
          <span className="font-semibold">A human in the loop across all of it.</span>{" "}
          <span className="text-muted">
            The agent finds, prioritizes and fixes — but anything consequential waits for one tap of your
            approval, and every decision is signed into a tamper-evident ledger. Autonomy where it&apos;s earned.
          </span>
        </p>
      </Reveal>
    </section>
  );
}
