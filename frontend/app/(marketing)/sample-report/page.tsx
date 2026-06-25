import Link from "next/link";
import { FileText, ArrowRight, ShieldAlert } from "lucide-react";
import { pageMeta } from "@/lib/seo";
import { SAMPLE_META, SAMPLE_COUNTS, SAMPLE_FINDINGS, SAMPLE_FRAMEWORKS, type SampleFinding } from "@/lib/sample-report";

export const metadata = pageMeta({
  title: "Sample Security Assessment Report | TensorShield",
  description:
    "See exactly what a TensorShield security assessment report looks like — a real, anonymized example with exploitation-proven findings, evidence, remediation, and SOC 2 / PCI / GDPR control mapping.",
  path: "/sample-report",
});

const SEV_TONE: Record<string, string> = {
  critical: "text-critical bg-critical/10 border-critical/30",
  high: "text-high bg-high/10 border-high/30",
  medium: "text-medium bg-medium/10 border-medium/30",
  low: "text-muted bg-surface-2 border-border",
};

export default function SampleReportPage() {
  return (
    <section className="mx-auto max-w-3xl px-5 pb-24 pt-16">
      <div className="text-center">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-accent">
          <FileText className="h-3.5 w-3.5" /> Sample report
        </span>
        <h1 className="mx-auto mt-3 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          What you actually get
        </h1>
        <p className="mx-auto mt-4 max-w-xl text-lg leading-relaxed text-muted">
          A real, fully-anonymized example of the security assessment report a customer receives — findings proven, not
          guessed, each with evidence, a fix, and the compliance controls it affects.
        </p>
      </div>

      {/* Report header */}
      <div className="mt-12 card p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs uppercase tracking-wide text-faint">Security Assessment Report</div>
            <div className="mt-1 text-xl font-semibold">{SAMPLE_META.org}</div>
            <div className="mono mt-0.5 text-xs text-muted">{SAMPLE_META.target}</div>
          </div>
          <div className="text-right text-xs text-faint">
            <div>{new Date(SAMPLE_META.date).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</div>
            <div className="mono mt-0.5">{SAMPLE_META.engine}</div>
            <div className="mt-2 inline-flex items-center gap-1 rounded-full bg-high/10 px-2 py-0.5 text-[11px] font-semibold text-high">
              <ShieldAlert className="h-3 w-3" /> Risk: {SAMPLE_META.riskRating}
            </div>
          </div>
        </div>
        <div className="mt-5 grid grid-cols-3 gap-3 sm:grid-cols-6">
          <Stat n={SAMPLE_COUNTS.critical} label="Critical" tone="text-critical" />
          <Stat n={SAMPLE_COUNTS.high} label="High" tone="text-high" />
          <Stat n={SAMPLE_COUNTS.medium} label="Medium" tone="text-medium" />
          <Stat n={SAMPLE_COUNTS.low} label="Low" tone="text-muted" />
          <Stat n={SAMPLE_COUNTS.exploitProven} label="Exploit-proven" tone="text-critical" />
          <Stat n={SAMPLE_COUNTS.verified} label="Verified" tone="text-pulse" />
        </div>
        <div className="mt-5 border-t border-border pt-4">
          <div className="text-[11px] uppercase tracking-wide text-faint">Scope</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {SAMPLE_META.scope.map((s) => (
              <span key={s} className="rounded-md bg-surface-2 px-2 py-0.5 text-[11px] text-muted">{s}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Findings */}
      <h2 className="mt-10 mb-4 text-sm font-semibold uppercase tracking-wider text-ink">Findings</h2>
      <div className="space-y-4">
        {SAMPLE_FINDINGS.map((f) => (
          <FindingCard key={f.id} f={f} />
        ))}
      </div>

      {/* Compliance */}
      <h2 className="mt-10 mb-4 text-sm font-semibold uppercase tracking-wider text-ink">Compliance posture</h2>
      <div className="card divide-y divide-border p-0">
        {SAMPLE_FRAMEWORKS.map((fr) => {
          const pct = Math.round((fr.met / fr.total) * 100);
          return (
            <div key={fr.name} className="flex items-center gap-3 px-5 py-3">
              <span className="w-32 shrink-0 text-sm font-medium">{fr.name}</span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                <div className="h-full rounded-full bg-pulse" style={{ width: `${pct}%` }} />
              </div>
              <span className="w-20 shrink-0 text-right text-xs text-muted">{fr.met}/{fr.total} · {pct}%</span>
            </div>
          );
        })}
      </div>

      {/* CTA */}
      <div className="mt-12 rounded-2xl border border-accent/30 bg-accent-soft/30 p-6 text-center">
        <p className="text-sm font-semibold">Get this report for your own company — free.</p>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-muted">
          Connect one system and TensorShield produces this, proves which findings are real, and writes the fixes — you
          approve anything that matters.
        </p>
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <Link href="/signup" className="inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover active:translate-y-px">
            Get my report — free <ArrowRight className="h-4 w-4" />
          </Link>
          <Link href="/scan" className="inline-flex items-center gap-2 rounded-xl border border-border px-5 py-2.5 text-sm font-medium transition hover:border-accent/40 hover:text-accent">
            Or run the 30-second external scan
          </Link>
        </div>
      </div>
    </section>
  );
}

function Stat({ n, label, tone }: { n: number; label: string; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface-2 px-2 py-2 text-center">
      <div className={`text-xl font-semibold ${tone}`}>{n}</div>
      <div className="text-[10px] uppercase tracking-wide text-faint">{label}</div>
    </div>
  );
}

function FindingCard({ f }: { f: SampleFinding }) {
  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-semibold capitalize ${SEV_TONE[f.severity]}`}>{f.severity}</span>
        <span className="text-sm font-semibold">{f.title}</span>
        <span className="ml-auto inline-flex items-center gap-1 rounded-full bg-pulse-soft px-2 py-0.5 text-[10px] font-medium text-pulse">{f.status}</span>
      </div>
      <div className="mono mt-1.5 text-[11px] text-faint">{f.asset} · {f.cwe} · CVSS {f.cvss}</div>
      <p className="mt-2 text-sm text-muted">{f.description}</p>
      <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
        <div className="rounded-lg bg-surface-2/60 p-2.5">
          <div className="font-semibold text-ink">Evidence</div>
          <p className="mt-0.5 text-muted">{f.evidence}</p>
        </div>
        <div className="rounded-lg bg-surface-2/60 p-2.5">
          <div className="font-semibold text-ink">Remediation</div>
          <p className="mt-0.5 text-muted">{f.remediation}</p>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {f.controls.map((c) => (
          <span key={c} className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] text-faint">{c}</span>
        ))}
      </div>
    </div>
  );
}
