import { ShieldQuestion, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import { Empty, SeverityBadge } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { SECURITY_TABS } from "@/lib/tabs";
import { ReinstateButton } from "@/components/verify/reinstate-button";

export const dynamic = "force-dynamic";

// The security engineer's verification surface.
//
// Every other screen shows what the AI decided to show. This one shows what it decided to HIDE, with
// the evidence to judge that call and a way to reverse it. Practitioners are explicit that they trust
// AI output only as far as they can verify it — and a filter that silently drops findings is the part
// they cannot verify from anywhere else in the product, because a dismissed finding has no row in any
// list, issue or incident.
export default async function VerifyPage() {
  const audit = await api.l15Audit();
  const nothingRecorded = audit.total === 0;

  return (
    <div className="space-y-6">
      <PageTabs tabs={SECURITY_TABS} />
      <PageIntro
        icon={ShieldQuestion}
        title="Verify"
        description="What the automated filter suppressed or changed, with the findings themselves so you can judge the call — and put back anything it got wrong. Every decision here was made by a rule, not a person."
      />

      {nothingRecorded ? (
        <Empty>
          {audit.note ??
            "Nothing has been suppressed or changed yet."}
        </Empty>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-3">
            <Stat label="Dropped" value={audit.dropped} hint="removed from every list — visible only here" />
            <Stat label="Demoted" value={audit.demoted} hint="shown, but at a lower severity than the tool assigned" />
            <Stat label="Scans audited" value={`${audit.scans_with_audit}/${audit.scans_total}`} hint="scans that recorded a trail" />
          </div>

          {/* Per-rule roll-up: one rule quietly suppressing many findings is the decision most worth
              arguing with, and it is invisible until grouped this way. */}
          {audit.by_rule.length > 0 && (
            <section className="rounded-2xl border border-border bg-surface">
              <header className="border-b border-border px-5 py-3">
                <h2 className="font-semibold">Which rules are doing this</h2>
                <p className="mt-0.5 text-sm text-muted">Noisiest first. A rule near the top is one to review.</p>
              </header>
              <ul className="divide-y divide-border">
                {audit.by_rule.map((r) => (
                  <li key={`${r.rule}:${r.action}`} className="flex items-center justify-between px-5 py-2.5 text-sm">
                    <span className="mono truncate text-muted">{r.rule}</span>
                    <span className="ml-4 shrink-0 text-muted">
                      <span className="font-medium text-ink">{r.count}</span> {r.action}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="rounded-2xl border border-border bg-surface">
            <header className="border-b border-border px-5 py-4">
              <h2 className="font-semibold">Suppressed findings</h2>
              <p className="mt-0.5 text-sm text-muted">
                These were dropped before they reached your queue. Reinstating one records that you overrode
                the filter, so it is never mistaken for a finding the system approved.
              </p>
            </header>
            {audit.suppressed.length === 0 ? (
              <p className="px-5 py-4 text-sm text-muted">
                Findings were changed on this estate, but none were dropped outright — see the rule list above.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {audit.suppressed.map((f) => (
                  <li key={f.id} className="flex items-start gap-3 px-5 py-3">
                    <SeverityBadge severity={f.severity} />
                    <div className="min-w-0 flex-1">
                      <p className="font-medium">{f.title}</p>
                      <p className="mono mt-0.5 truncate text-xs text-faint">
                        {f.rule_id}
                        {f.endpoint ? ` · ${f.endpoint}` : ""}
                      </p>
                      {f.description ? <p className="mt-1 text-sm text-muted">{f.description}</p> : null}
                    </div>
                    <ReinstateButton findingId={f.id} />
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}

      <p className="flex items-start gap-2 text-xs text-muted">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
        An empty page here means nothing was <em>recorded</em> as suppressed — scans that ran before this
        trail existed, or with enrichment disabled, leave none. That is not the same as nothing having
        been suppressed.
      </p>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: number | string; hint: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface px-4 py-3">
      <div className="text-2xl font-semibold text-ink">{value}</div>
      <div className="text-sm font-medium">{label}</div>
      <div className="mt-0.5 text-xs text-muted">{hint}</div>
    </div>
  );
}
