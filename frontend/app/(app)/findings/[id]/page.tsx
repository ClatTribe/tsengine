import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ShieldAlert, Flame } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Tag } from "@/components/ui/primitives";
import { RequestReview } from "@/components/reviews/request-review";

export const dynamic = "force-dynamic";

const FW_LABEL: Record<string, string> = {
  soc2: "SOC 2", iso27001: "ISO 27001", pci: "PCI", hipaa: "HIPAA", cis_v8: "CIS v8", nist_csf: "NIST CSF",
};

export default async function FindingDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [f, reviews] = await Promise.all([api.finding(id), api.reviews()]);
  if (!f) notFound();

  const kev = !!f.threat_intel?.kev;
  const epss = !!f.threat_intel?.epss;
  const controls = Object.entries(f.compliance ?? {}).filter(([, v]) => Array.isArray(v) && v.length > 0);
  const hasOpenReview = reviews.some((r) => r.subject_id === id && r.status === "open");

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <Link href="/findings" className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Findings
      </Link>

      <div className="flex items-start gap-3">
        <div className="mt-0.5 grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-border bg-surface-2 text-high">
          <ShieldAlert className="h-5 w-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={f.severity} />
            {f.verification_status && <Tag>{f.verification_status}</Tag>}
            {typeof f.confidence === "number" && f.confidence > 0 && <span className="text-xs text-faint">confidence {f.confidence.toFixed(2)}</span>}
          </div>
          <h1 className="mt-1.5 text-xl font-semibold leading-tight">{f.title}</h1>
        </div>
      </div>

      {kev && (
        <div className="flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-critical">
          <Flame className="h-4 w-4" /> Listed in CISA KEV — actively exploited in the wild.{epss ? " EPSS available." : ""}
        </div>
      )}

      <RequestReview subjectId={f.id} hasOpenReview={hasOpenReview} />

      <div className="card space-y-3 p-5">
        <Row label="Tool" value={<Tag>{f.tool}</Tag>} />
        <Row label="Rule" value={<code className="mono rounded border border-border bg-bg px-1.5 py-0.5 text-xs">{f.rule_id}</code>} />
        {f.endpoint && <Row label="Endpoint" value={<code className="mono break-all rounded border border-border bg-bg px-1.5 py-0.5 text-xs">{f.endpoint}</code>} />}
        {f.cwe && f.cwe.length > 0 && <Row label="CWE" value={<div className="flex flex-wrap gap-1">{f.cwe.map((c) => <Tag key={c}>{c}</Tag>)}</div>} />}
        {f.mitre_techniques && f.mitre_techniques.length > 0 && (
          <Row label="MITRE" value={<div className="flex flex-wrap gap-1">{f.mitre_techniques.map((m) => <Tag key={m}>{m}</Tag>)}</div>} />
        )}
      </div>

      {f.description && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Description</div>
          <div className="card p-5 text-sm leading-relaxed text-muted">{f.description}</div>
        </section>
      )}

      {controls.length > 0 && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Affected controls</div>
          <div className="card space-y-1.5 p-5">
            {controls.map(([fw, ids]) => (
              <div key={fw} className="text-sm">
                <span className="text-muted">{FW_LABEL[fw] ?? fw}:</span> <span className="mono">{(ids as string[]).join(", ")}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3">
      <div className="w-20 shrink-0 text-xs text-muted">{label}</div>
      <div className="min-w-0 text-sm">{value}</div>
    </div>
  );
}
