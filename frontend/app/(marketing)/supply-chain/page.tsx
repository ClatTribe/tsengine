import Link from "next/link";
import {
  Boxes, ArrowRight, Skull, CalendarX, Archive, Scale, GitBranch, Wrench,
  Fingerprint, CheckCircle2, XCircle, Minus, Bot, ShieldCheck,
} from "lucide-react";

export const metadata = {
  title: "Supply-chain security — malware, EOL, license & reachability | TensorShield",
  description:
    "Your dependencies are the attack surface. TensorShield checks every package for malicious code, end-of-life runtimes, abandoned packages, risky licenses, and reachable CVEs — grounded, low-noise, and fixed on approval.",
};

// The five dependency-risk checks (the supply-chain composition story).
const CHECKS = [
  { icon: Skull, t: "Malicious packages", d: "Typosquatted, backdoored, and hijacked packages (ua-parser-js, node-ipc, PyPI typosquats) — hostile by design, usually carrying no CVE. Matched against the OSSF malicious-packages / OSV feed.", sev: "Critical" },
  { icon: CalendarX, t: "End-of-life runtimes", d: "Python 2, Node 12/14, PHP 7.4, Django 2.2 and other cycles past their published support date — no more security patches, so exposure only grows. Grounded in endoflife.date.", sev: "High" },
  { icon: Archive, t: "Deprecated / abandoned", d: "Packages the maintainer has officially deprecated (request, node-uuid, nose) — with the recommended replacement. The actionable core of package health.", sev: "Med / Low" },
  { icon: Scale, t: "License risk", d: "Copyleft obligations in proprietary or SaaS code — AGPL (network copyleft) and GPL flagged from the SBOM, the permissive majority left silent.", sev: "Med / Low" },
  { icon: GitBranch, t: "Reachable CVEs", d: "Go call-graph reachability (govulncheck): the CVEs whose vulnerable code is actually called rise above the unreachable majority — cutting SCA noise at the root.", sev: "Prioritised" },
];

const DIFF = [
  { icon: Fingerprint, t: "Grounded — not a noise flood", d: "Every finding is a corpus match or a real config fact, never a heuristic guess. A clean dependency set returns zero findings, so the alerts you do get are real." },
  { icon: Bot, t: "Fixed, not just flagged", d: "The agentic layer prepares the actual remediation — the upgrade PR, the replacement, the pin — and ships it the moment you approve. A finding is the start, not the end." },
  { icon: ShieldCheck, t: "On the best-in-class OSS", d: "Built on the same leading open-source scanners the rest of the industry trusts (syft, trivy, grype, govulncheck) — with an AI security engineer and a signed evidence trail on top." },
];

const COMPARE: { label: string; cells: string[] }[] = [
  { label: "Known-CVE dependencies (SCA)", cells: ["yes", "yes"] },
  { label: "Malicious / typosquatted packages", cells: ["yes", "part"] },
  { label: "End-of-life runtimes & frameworks", cells: ["yes", "no"] },
  { label: "Deprecated / abandoned packages", cells: ["yes", "no"] },
  { label: "License-obligation risk (AGPL/GPL)", cells: ["yes", "part"] },
  { label: "Reachability — cut the unreachable-CVE noise", cells: ["yes", "no"] },
  { label: "Ships the fix on approval (PR / pin)", cells: ["yes", "no"] },
  { label: "Signed, compliance-mapped evidence", cells: ["yes", "no"] },
];

export default function SupplyChain() {
  return (
    <>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-x-0 -top-40 h-80 bg-gradient-to-b from-accent-soft/60 to-transparent" />
        <div className="relative mx-auto max-w-3xl px-5 pb-12 pt-20 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted shadow-sm">
            <Boxes className="h-3.5 w-3.5 text-accent" /> Software supply-chain security
          </span>
          <h1 className="mt-6 text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl">
            Your dependencies are the attack surface.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-relaxed text-muted">
            Most breaches now start in a package you didn&apos;t write. TensorShield checks every dependency for
            malicious code, end-of-life runtimes, abandoned packages, risky licenses, and reachable CVEs — grounded,
            low-noise, and fixed the moment you approve.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px"
            >
              Scan your dependencies <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/product"
              className="inline-flex items-center gap-2 rounded-xl border border-border bg-surface px-5 py-3 text-sm font-semibold text-ink shadow-sm transition hover:border-border-strong"
            >
              See how it works
            </Link>
          </div>
          <p className="mt-4 text-xs text-faint">One SBOM, five risk classes · grounded · zero findings on a clean tree</p>
        </div>
      </section>

      {/* The five checks */}
      <section className="mx-auto max-w-6xl px-5 pb-4 pt-8">
        <div className="mx-auto mb-10 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">Beyond known CVEs</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">Five risks in every dependency tree.</h2>
          <p className="mt-3 text-base leading-relaxed text-muted">
            A CVE scanner only sees known bugs in legitimate code. We generate one SBOM and run five grounded checks
            across it — the risks that actually compromise SMBs.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CHECKS.map(({ icon: Icon, t, d, sev }) => (
            <div key={t} className="card p-5">
              <div className="flex items-center justify-between">
                <span className="grid h-9 w-9 place-items-center rounded-lg bg-accent-soft text-accent">
                  <Icon className="h-4 w-4" />
                </span>
                <span className="rounded-full border border-border bg-bg px-2 py-0.5 text-[11px] font-medium text-faint">{sev}</span>
              </div>
              <h3 className="mt-3.5 text-sm font-semibold">{t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Differentiators */}
      <section className="bg-surface">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Why it&apos;s different</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">
              Grounded findings, on best-in-class OSS, that fix themselves.
            </h2>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {DIFF.map(({ icon: Icon, t, d }) => (
              <div key={t} className="card bg-bg p-6">
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

      {/* How it works */}
      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="mx-auto mb-12 max-w-2xl text-center">
          <span className="text-xs font-semibold uppercase tracking-wider text-accent">How it works</span>
          <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">One SBOM in, real risk out.</h2>
        </div>
        <div className="grid gap-5 md:grid-cols-4">
          {[
            { step: "1", icon: Boxes, t: "Generate the SBOM", d: "Syft inventories every direct + transitive dependency across your repos and images — the complete bill of materials." },
            { step: "2", icon: Fingerprint, t: "Match, grounded", d: "Each package is checked against authoritative corpora (malware, EOL, deprecation, license) and Go reachability — a finding only on a real match." },
            { step: "3", icon: Wrench, t: "Prepare the fix", d: "The agent drafts the upgrade / replacement / pin, mapped to CWE-506/1104 and the compliance controls it touches." },
            { step: "4", icon: CheckCircle2, t: "You approve", d: "One tap ships the PR. Everything signed into a tamper-evident ledger for the auditor and the customer." },
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

      {/* Compare vs a plain SCA scanner */}
      <section className="bg-surface">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <div className="mx-auto mb-12 max-w-2xl text-center">
            <span className="text-xs font-semibold uppercase tracking-wider text-accent">Vs a plain SCA scanner</span>
            <h2 className="mt-3 text-3xl font-semibold leading-tight tracking-tight">CVE scanning is table stakes. This is the rest.</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-separate border-spacing-0 text-sm">
              <thead>
                <tr>
                  <th className="w-[58%] p-0" />
                  {[
                    { name: "TensorShield", sub: "supply-chain", highlight: true },
                    { name: "Plain SCA", sub: "CVE scanner", highlight: false },
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
          <p className="mt-4 text-center text-[11px] text-faint">
            Category comparison — capabilities vary by vendor and plan. &quot;Plain SCA&quot; is a CVE-only dependency scanner.
          </p>
        </div>
      </section>

      {/* CTA band */}
      <section className="relative overflow-hidden bg-gradient-to-br from-accent via-[#4338CA] to-[#3730A3]">
        <div className="absolute -right-20 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-5 py-20 text-center text-white">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Find the risk in your dependencies — free.</h2>
          <p className="mx-auto mt-3 max-w-lg text-white/75">
            Connect a repo and see malicious, end-of-life, abandoned, and risky-licensed packages in minutes — with the
            fix ready to ship.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-semibold text-accent shadow-sm transition hover:bg-white/90">
              Start free <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/vapt" className="inline-flex items-center gap-2 rounded-xl bg-white/10 px-5 py-3 text-sm font-semibold text-white ring-1 ring-white/20 transition hover:bg-white/15">
              See the VAPT report
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
