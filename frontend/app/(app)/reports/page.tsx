import Link from "next/link";
import { FileText, Download, ShieldCheck, FileCode2, Sheet, Lock, ArrowUpRight } from "lucide-react";
import { api, FRAMEWORKS, FRAMEWORK_LABEL } from "@/lib/api";
import { Card, SectionTitle, Empty } from "@/components/ui/primitives";

export const dynamic = "force-dynamic";

export default async function ReportsPage() {
  const frameworks = (
    await Promise.all(
      FRAMEWORKS.map(async (f) => {
        const cs = await api.posture(f);
        if (cs.length === 0) return null;
        const gap = cs.filter((c) => c.state === "gap").length;
        const pct = Math.round(((cs.length - gap) / cs.length) * 100);
        return { f, total: cs.length, met: cs.length - gap, gap, pct };
      }),
    )
  ).filter(Boolean) as { f: string; total: number; met: number; gap: number; pct: number }[];

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Reports &amp; evidence</h1>
        <p className="text-xs text-muted">Signed, auditor-ready exports of your posture and findings — generated from real data, not screenshots.</p>
      </div>

      {/* VAPT / pentest report — the headline deliverable for a customer security review */}
      <div>
        <SectionTitle>Vulnerability assessment &amp; pentest (VAPT)</SectionTitle>
        <Card className="flex items-center gap-4 p-5">
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-sm">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">VAPT / penetration-test report</div>
            <div className="text-xs text-muted">
              Executive summary, scope, and every finding with severity, CWE/CVSS, exploit status &amp; evidence — the
              document an enterprise customer or insurer asks for. Continuously regenerated, grounded in real scans.
            </div>
          </div>
          <a
            href="/api/vapt"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white transition hover:bg-accent-hover active:translate-y-px"
          >
            <Download className="h-3.5 w-3.5" /> Download
          </a>
        </Card>
      </div>

      {/* Compliance evidence packs */}
      <div>
        <SectionTitle>Compliance evidence packs</SectionTitle>
        <Card className="p-0">
          {frameworks.length === 0 ? (
            <div className="p-5"><Empty>No control state yet — evidence packs appear as findings map to controls.</Empty></div>
          ) : (
            <ul className="divide-y divide-border">
              {frameworks.map(({ f, met, total, gap, pct }) => (
                <li key={f} className="flex items-center gap-4 px-5 py-3.5">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent-soft text-accent">
                    <ShieldCheck className="h-4 w-4" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium">{FRAMEWORK_LABEL[f] ?? f}</div>
                    <div className="text-xs text-muted">
                      {met}/{total} controls met · {gap === 0 ? "on track" : `${gap} gap${gap > 1 ? "s" : ""}`}
                    </div>
                  </div>
                  <span className={`text-sm font-semibold ${pct === 100 ? "text-pulse" : "text-ink"}`}>{pct}%</span>
                  <a
                    href={`/api/report?framework=${f}`}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border bg-surface px-2.5 py-1.5 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-ink active:translate-y-px"
                  >
                    <Download className="h-3.5 w-3.5" /> Report
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <p className="mt-2 text-[11px] text-faint">
          Each pack is ed25519-signed over its canonical contents and pinned to the state it was assessed against — an
          auditor can verify it, and re-run the evidence predicate.
        </p>
      </div>

      {/* Findings exports */}
      <div>
        <SectionTitle action={<Link href="/findings" className="text-[11px] font-medium text-accent hover:underline">all findings →</Link>}>
          Findings exports
        </SectionTitle>
        <Card className="grid gap-3 p-5 sm:grid-cols-2">
          <ExportTile href="/api/export?format=sarif" icon={FileCode2} title="SARIF" sub="For GitHub code scanning & CI gates" />
          <ExportTile href="/api/export?format=csv" icon={Sheet} title="CSV" sub="For spreadsheets & ticketing imports" />
        </Card>
      </div>

      {/* Questionnaire shortcut */}
      <div>
        <SectionTitle>Security questionnaires</SectionTitle>
        <Card className="flex items-center gap-4 p-5">
          <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
            <FileText className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-medium">Auto-answered security questionnaire</div>
            <div className="text-xs text-muted">CAIQ / SIG-style answers, grounded in your live posture — for procurement & vendor reviews.</div>
          </div>
          <Link href="/compliance/questionnaire" className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-accent hover:underline">
            Open <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        </Card>
      </div>

      <p className="flex items-center justify-center gap-1.5 text-[11px] text-faint">
        <Lock className="h-3 w-3" /> Downloads are proxied server-side — your token never reaches the browser.
      </p>
    </div>
  );
}

function ExportTile({ href, icon: Icon, title, sub }: { href: string; icon: typeof FileCode2; title: string; sub: string }) {
  return (
    <a
      href={href}
      className="group flex items-center gap-3 rounded-xl border border-border bg-surface-2 p-3.5 transition hover:border-accent/40 active:translate-y-px"
    >
      <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-surface text-muted group-hover:text-accent">
        <Icon className="h-4 w-4" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-muted">{sub}</div>
      </div>
      <Download className="h-4 w-4 shrink-0 text-faint transition group-hover:text-accent" />
    </a>
  );
}
