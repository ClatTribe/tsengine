import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ShieldAlert, Flame, Wrench, GitPullRequest, Settings2, Ticket, FileWarning, ArrowRight, Radar, FileCode2 } from "lucide-react";
import { api } from "@/lib/api";
import { FRAMEWORK_LABEL } from "@/lib/frameworks";
import { AutofixButton } from "@/components/findings/autofix-button";
import { SeverityBadge, Tag } from "@/components/ui/primitives";
import { RequestReview } from "@/components/reviews/request-review";
import type { Action } from "@/lib/types";

export const dynamic = "force-dynamic";

const ACTION_META: Record<string, { icon: typeof Wrench; label: string }> = {
  open_pr: { icon: GitPullRequest, label: "Pull request with the fix" },
  apply_config: { icon: Settings2, label: "Configuration change" },
  file_ticket: { icon: Ticket, label: "Remediation ticket" },
  draft_notification: { icon: FileWarning, label: "Breach disclosure draft" },
};

export default async function FindingDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [f, reviews, approvals] = await Promise.all([api.finding(id), api.reviews(), api.approvals()]);
  if (!f) notFound();

  const kev = !!f.threat_intel?.kev;
  const epss = !!f.threat_intel?.epss;
  const controls = Object.entries(f.compliance ?? {}).filter(([, v]) => Array.isArray(v) && v.length > 0);
  const hasOpenReview = reviews.some((r) => r.subject_id === id && r.status === "open");
  // The remediation the agent has queued for THIS finding (if any) — the agentic signal.
  const action = approvals.find((a) => a.finding_id === id);

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

      <AgentCard action={action} />

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

      <section>
        <div className="mb-2 text-xs uppercase tracking-wider text-muted">AI fix</div>
        <div className="card p-5">
          <p className="mb-3 text-sm text-muted">
            Generate a concrete code patch for this finding, grounded in the evidence above. A named owner reviews
            and merges it.
          </p>
          <AutofixButton id={id} />
        </div>
      </section>

      {f.code_provenance && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Fix in code (Cloud-to-Code)</div>
          <div className="card border-accent/40 bg-accent-soft/30 p-5">
            <div className="flex items-start gap-3">
              <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent text-white shadow-sm">
                <FileCode2 className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold">This runtime issue was provisioned by Infrastructure-as-Code</div>
                <p className="mt-1 text-sm leading-relaxed text-muted">
                  Fix it at the source — patching the live resource will be undone by the next deploy.
                </p>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <code className="mono rounded border border-border bg-bg px-2 py-1 text-xs">
                    {f.code_provenance.file}:{f.code_provenance.line}
                  </code>
                  <Tag>{f.code_provenance.iac_resource}</Tag>
                  <span className="rounded-full bg-surface-2 px-2 py-0.5 text-[11px] text-muted">
                    {f.code_provenance.confidence} confidence
                  </span>
                </div>
                <p className="mt-3 text-xs leading-relaxed text-faint">
                  {f.code_provenance.match_basis} — matched on{" "}
                  <code className="mono">{f.code_provenance.matched_on}</code>
                </p>
              </div>
            </div>
          </div>
        </section>
      )}

      {controls.length > 0 && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Affected controls</div>
          <div className="card space-y-1.5 p-5">
            {controls.map(([fw, ids]) => (
              <div key={fw} className="text-sm">
                <span className="text-muted">{FRAMEWORK_LABEL[fw] ?? fw}:</span> <span className="mono">{(ids as string[]).join(", ")}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

// AgentCard surfaces what TensorShield is DOING about this finding — the human-in-the-loop
// signal on the detail page. Grounded: it only claims a queued fix when a real gated action
// references this finding; otherwise it states the honest monitoring posture.
function AgentCard({ action }: { action?: Action }) {
  if (action) {
    const meta = ACTION_META[action.kind] ?? { icon: Wrench, label: action.kind };
    const Icon = meta.icon;
    const t3 = action.tier >= 3;
    return (
      <div className="card border-accent/40 bg-accent-soft/30 p-5">
        <div className="flex items-start gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-accent text-white shadow-sm">
            <Icon className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold">TensorShield prepared a fix for this</div>
            <div className="mt-0.5 text-xs text-muted">
              {action.title || meta.label} · {t3 ? "needs your signature" : "awaiting your approval"} · tier {action.tier}
            </div>
            <p className="mt-2 text-sm text-muted">
              {t3
                ? "This is irreversible — the agent drafted it and is holding for a named human to review and sign."
                : "The agent generated the remediation and is holding for your decision. Nothing is applied until you approve."}
            </p>
          </div>
          <Link
            href="/inbox"
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white transition hover:bg-accent-hover"
          >
            Review <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>
    );
  }
  return (
    <div className="card flex items-center gap-2.5 p-4 text-sm text-muted">
      <Radar className="h-4 w-4 shrink-0 text-faint" />
      TensorShield is monitoring this finding — nothing is awaiting your approval right now.
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
