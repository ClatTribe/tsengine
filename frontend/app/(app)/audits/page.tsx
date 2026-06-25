import { FileCheck2, ShieldCheck, UserCheck } from "lucide-react";
import { api } from "@/lib/api";
import type { AuditEngagement } from "@/lib/types";
import { Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { CreateAudit } from "@/components/audits/create-audit";
import { AttestControl } from "@/components/audits/attest-control";
import { issueAudit } from "./actions";

export const dynamic = "force-dynamic";

const FRAMEWORK_LABEL: Record<string, string> = {
  soc2: "SOC 2", iso27001: "ISO 27001", pci: "PCI-DSS", hipaa: "HIPAA", nist_csf: "NIST CSF", gdpr: "GDPR",
};
const STATUS_TONE: Record<string, string> = { planning: "text-muted", fieldwork: "text-accent", issued: "text-pulse" };

export default async function AuditsPage() {
  const { audits } = await api.audits();
  const issued = audits.filter((a) => a.status === "issued").length;

  return (
    <div className="space-y-6">
      <PageIntro
        icon={FileCheck2}
        title="Audits"
        description="Run your SOC 2 / ISO audit with an external auditor. TensorShield assembles the controls to attest from your live posture and tracks the engagement — but the attestation is the independent auditor's, by name. Audit-ready, not the audit."
        right={
          <div className="flex items-center gap-4">
            <div className="text-right text-sm">
              <span className="text-xl font-semibold text-pulse">{issued}</span> <span className="text-xs text-faint">issued</span>
            </div>
            <CreateAudit />
          </div>
        }
      />

      {audits.length === 0 ? (
        <Empty>No audit engagements yet. Open one to seed the controls your auditor will attest.</Empty>
      ) : (
        <div className="space-y-4">
          {audits.map((a) => (
            <AuditCard key={a.id} a={a} />
          ))}
        </div>
      )}
    </div>
  );
}

function AuditCard({ a }: { a: AuditEngagement }) {
  const s = a.summary;
  const attestations = a.attestations ?? [];
  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-center gap-2.5">
        <FileCheck2 className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold">{FRAMEWORK_LABEL[a.framework] ?? a.framework}</span>
        <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase text-faint">{a.audit_type === "type_ii" ? "Type II" : "Type I"}</span>
        <span className={`text-xs font-medium capitalize ${STATUS_TONE[a.status] ?? "text-muted"}`}>{a.status}</span>
        {a.ledger_ref && (
          <span className="inline-flex items-center gap-1 text-[11px] text-pulse">
            <ShieldCheck className="h-3 w-3" /> signed
          </span>
        )}
        <span className="ml-auto text-xs text-muted">{s.percent}% attested</span>
      </div>

      {/* auditor + progress */}
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-faint">
        {a.auditor_name && (
          <span className="inline-flex items-center gap-1">
            <UserCheck className="h-3 w-3" /> {a.auditor_name}
            {a.auditor_firm ? `, ${a.auditor_firm}` : ""}
          </span>
        )}
        <span>{s.passed} passed · {s.exceptions} exception{s.exceptions === 1 ? "" : "s"} · {s.pending} pending</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full rounded-full bg-pulse" style={{ width: `${s.percent}%` }} />
      </div>

      {/* controls to attest */}
      {attestations.length > 0 && (
        <div className="mt-4 space-y-1.5">
          {attestations.map((c) => (
            <AttestControl key={c.control_id} id={a.id} c={c} auditorName={a.auditor_name ?? ""} />
          ))}
        </div>
      )}

      {/* issue */}
      {a.status !== "issued" && (
        <form action={issueAudit} className="mt-4 flex items-center gap-3">
          <input type="hidden" name="id" value={a.id} />
          <button
            type="submit"
            disabled={!s.ready}
            title={s.ready ? "Mark the engagement issued" : "Every control must be attested (no exceptions/pending) first"}
            className="rounded-lg border border-pulse/40 px-3.5 py-1.5 text-sm font-medium text-pulse transition hover:bg-pulse/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Mark issued
          </button>
          {!s.ready && <span className="text-xs text-faint">Issuable once every control is attested with no exceptions.</span>}
        </form>
      )}
    </div>
  );
}
