import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ShieldAlert, Flame, Wrench, GitPullRequest, Settings2, Ticket, FileWarning, ArrowRight, Radar, FileCode2 } from "lucide-react";
import { api } from "@/lib/api";
import { LocalizeFinding } from "@/components/findings/localize-finding";
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

// Metasploit's own scale, in the responder's terms. Their words, not a grading we invented on top
// of their numbers — the ranks mean specific things to the people who publish them.
const WEAPON_RANK: Record<string, string> = {
  excellent: "runs reliably and will not crash the service",
  great: "reliable against a known target",
  good: "works against a common default configuration",
  normal: "works, but is version-specific",
  average: "unreliable",
  low: "rarely works",
  manual: "needs hand-holding and may not work",
};

export default async function FindingDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [f, reviews, approvals] = await Promise.all([api.finding(id), api.reviews(), api.approvals()]);
  if (!f) notFound();

  const ti = f.threat_intel;
  const kev = !!ti?.kev?.listed;
  const cvss = typeof ti?.cvss === "number" && ti.cvss > 0 ? ti.cvss : null;
  const cvssVector = ti?.cvss_vector || null;
  const epssPct = typeof ti?.epss?.score === "number" ? Math.round(ti.epss.score * 100) : null;
  const publicExploit = Array.isArray(ti?.exploits) && ti.exploits.length > 0;
  // "A public exploit exists" is where this used to stop, and it reads the same for a module that
  // runs reliably and one that barely works. Metasploit's own rank is the difference between "someone
  // capable could" and "anyone can, tonight" — the thing a responder is actually deciding on.
  const weaponLabel = WEAPON_RANK[String(ti?.weapon_rank ?? "").toLowerCase()] ?? null;
  const derivedFrom = Array.isArray(f.derived_from) ? f.derived_from : [];
  // Our own assessment, shown as ours. Deliberately NOT labelled a promotion: the audit entry that
  // records a severity bump lives on the scan's l15_audit_log, not on the finding, so this page
  // cannot prove one happened — and claiming it would be exactly the ungrounded inference the rest
  // of this file avoids. Stating the assessment and its reason is what the page can honestly say.
  const exploitReason = f.exploitability?.reason || null;
  const exploitScore = typeof f.exploitability?.score === "number" ? f.exploitability.score : null;
  const hasThreatIntel = kev || cvss !== null || epssPct !== null || publicExploit || exploitReason !== null;
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
          <Flame className="h-4 w-4" /> Listed in CISA KEV — actively exploited in the wild.{ti?.kev?.date_added ? ` Added ${ti.kev.date_added.slice(0, 10)}.` : ""} Patch now (BOD 22-01).
        </div>
      )}

      {hasThreatIntel && (
        <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">Threat intelligence</div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-sm">
            {cvss !== null && (
              <span>
                <span className="text-faint">CVSS</span> <span className="font-medium text-ink">{cvss.toFixed(1)}</span>
                {cvssVector && <span className="mono ml-1 text-[11px] text-muted">{cvssVector}</span>}
              </span>
            )}
            {epssPct !== null && (
              <span title="FIRST.org EPSS — probability of exploitation in the next 30 days">
                <span className="text-faint">EPSS</span> <span className="font-medium text-ink">{epssPct}%</span>
              </span>
            )}
            {exploitReason && (
              <span title="tsengine's own exploitability assessment — this is our judgement, not the scanner's, and it can raise a finding's severity">
                <span className="text-faint">Exploitability</span>{" "}
                <span className="font-medium text-ink">{exploitScore !== null ? `${exploitScore}/100` : "rated"}</span>
                <span className="ml-1 text-muted">· {exploitReason}</span>
              </span>
            )}
            {publicExploit && (
              <span className="font-medium text-high">
                {weaponLabel
                  ? `Weaponized — Metasploit module, ${weaponLabel}`
                  : "Public exploit available (PoC published)"}
              </span>
            )}
          </div>
        </div>
      )}

      {derivedFrom.length > 0 && (
        // A DERIVED finding is not something a tool saw — it is a join across findings ("this leaked
        // key reaches that cloud role"). §10 requires every recorded issue to cite its evidence, and
        // for a derived finding the evidence IS these ids. The field carried them the whole time and
        // the page showed none of it, which is precisely the "assertion with nothing behind it" its
        // own Go doc says it exists to prevent.
        <div className="rounded-lg border border-border bg-surface-2 px-3 py-2.5">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Derived finding — what it rests on
          </div>
          <p className="mt-1 text-xs text-muted">
            Nothing observed this directly. It was derived by joining the{" "}
            {derivedFrom.length === 1 ? "finding" : `${derivedFrom.length} findings`} below; if{" "}
            {derivedFrom.length === 1 ? "it does" : "they do"} not hold, neither does this.
          </p>
          <ul className="mt-2 space-y-1">
            {derivedFrom.map((ref) => (
              <li key={ref}>
                <Link href={`/findings/${encodeURIComponent(ref)}`} className="mono text-xs text-accent hover:underline">
                  {ref}
                </Link>
              </li>
            ))}
          </ul>
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

      {/* LOCATE BEFORE FIX. A patch is only as good as knowing which file it belongs in, and a
          scanner's file:line is often approximate or absent — so this sits immediately above AI fix. */}
      <LocalizeFinding findingID={id} />

      {/* What the TOOL said — the scanner's own output and the exact arguments that produced it.
          Stored since Phase 0 and never shown until now. A security engineer verifies a finding by
          reading the tool's output rather than our summary of it, and cannot reproduce a result whose
          arguments they cannot see. It is collapsed by default: most readers want the summary, and
          the ones who want this really want it. */}
      {(f.raw_output != null || (f.tool_args && Object.keys(f.tool_args).length > 0) || f.discovery_method?.primary) && (
        <section>
          <div className="mb-2 text-xs uppercase tracking-wider text-muted">Tool evidence</div>
          <details className="card p-0">
            <summary className="cursor-pointer px-5 py-3 text-sm text-muted transition hover:text-ink">
              What {f.tool || "the tool"} actually reported
            </summary>
            <div className="space-y-4 border-t border-border px-5 py-4">
              {f.discovery_method?.primary && (
                <div>
                  <div className="mb-1 text-xs font-medium text-ink">How this was found</div>
                  <p className="text-xs text-muted">
                    {f.discovery_method.primary === "human_reinstated"
                      ? "Reinstated by a person after the automated filter dismissed it — a human vouched for this over the filter's objection."
                      : f.discovery_method.primary === "tool_replay"
                        ? "Produced by a tool re-run with custom arguments, not a scheduled scan."
                        : f.discovery_method.primary}
                  </p>
                </div>
              )}
              {f.tool_args && Object.keys(f.tool_args).length > 0 && (
                <div>
                  <div className="mb-1 text-xs font-medium text-ink">Arguments used</div>
                  <pre className="mono overflow-x-auto rounded border border-border bg-bg p-3 text-xs text-muted">
{Object.entries(f.tool_args).map(([k, v]) => `${k} ${v}`).join("\n")}
                  </pre>
                  <p className="mt-1 text-xs text-faint">Re-run the tool with these (or your own) arguments to reproduce it.</p>
                </div>
              )}
              {f.raw_output != null && (
                <div>
                  <div className="mb-1 text-xs font-medium text-ink">Raw output</div>
                  <pre className="mono max-h-96 overflow-auto rounded border border-border bg-bg p-3 text-xs text-muted">
{typeof f.raw_output === "string" ? f.raw_output : JSON.stringify(f.raw_output, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </details>
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
