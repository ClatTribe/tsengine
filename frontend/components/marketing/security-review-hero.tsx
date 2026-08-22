import { CheckCircle2, FileCheck2, Lock } from "lucide-react";

// The hero centrepiece: the artefact the buyer actually wants.
//
// This replaced <AttackPathHero />, a cloud-IAM escalation graph. That graph is a good picture and
// it is still correct — but it is the SECURITY ENGINEER's picture. It asks the reader to parse
// nodes and directed edges before they feel anything, and the person this page sells to is a
// founder or VP Eng whose deal is stuck in a customer's security review and who has no security
// team to read a graph for them. A hero that must be decoded is not doing a hero's job.
//
// So the hero now shows the OUTCOME they are buying: the review going from blocked to cleared, and
// the signed report they can send back. Same product, told from the buyer's side of the table. The
// attack-path graph moved to /ai-security-engineer, where the reader has opted into the mechanics.
//
// Honesty (CLAUDE.md §10): labelled "Example" in the same way the attack path was, because these
// rows are a representative questionnaire, not a real customer's assessment. The check names are
// the ones our own free scanner actually tests for (see /scan and the questionnaire blog post), so
// nothing here implies a capability that does not exist.

type Row = { label: string; detail: string; cleared: string };

const ROWS: Row[] = [
  { label: "Email spoofing protection", detail: "DMARC, SPF, DKIM", cleared: "Enforced" },
  { label: "Encryption in transit", detail: "HTTPS everywhere, HSTS", cleared: "Enforced" },
  { label: "Known vulnerabilities", detail: "code, cloud and dependencies", cleared: "0 open, high or above" },
  { label: "Access control", detail: "MFA on every admin", cleared: "Enforced" },
  { label: "Penetration test report", detail: "dated within 12 months", cleared: "Attached, signed" },
];

export function SecurityReviewHero() {
  return (
    <div className="card animate-fade-rise p-4 sm:p-5">
      <div className="mb-3 flex items-center gap-2 px-1 text-[11px] font-medium uppercase tracking-wider text-faint">
        <span className="pulse-dot" /> Example · your customer&apos;s security review
      </div>

      <ul className="space-y-1.5">
        {ROWS.map((r, i) => (
          <li
            key={r.label}
            className="animate-row-in flex items-center gap-3 rounded-xl border border-border bg-bg px-3 py-2.5"
            // Rows resolve in sequence, so the eye reads it as a review being worked through rather
            // than a static list. The global prefers-reduced-motion guard collapses the duration and
            // `both` holds the end state, so nothing is hidden from a reduced-motion reader.
            style={{ animationDelay: `${i * 130}ms` }}
          >
            <CheckCircle2 className="h-4 w-4 shrink-0 text-pulse" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[13px] font-medium text-ink">{r.label}</div>
              <div className="truncate text-[11px] leading-snug text-faint">{r.detail}</div>
            </div>
            <span className="shrink-0 rounded-md bg-pulse-soft px-2 py-1 text-[10.5px] font-semibold uppercase tracking-wide text-pulse">
              {r.cleared}
            </span>
          </li>
        ))}
      </ul>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
        <div className="flex items-center gap-2 text-[12px] text-muted">
          <FileCheck2 className="h-4 w-4 shrink-0 text-accent" />
          <span>
            Signed evidence pack — <span className="font-medium text-ink">ready to send back</span>
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-[11px] text-faint">
          <Lock className="h-3 w-3" /> you approved every change
        </div>
      </div>
    </div>
  );
}
