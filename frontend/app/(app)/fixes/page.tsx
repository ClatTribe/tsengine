import { ListOrdered } from "lucide-react";
import { api } from "@/lib/api";
import { Empty, SeverityBadge } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { SECURITY_TABS } from "@/lib/tabs";
import { PrepareStep } from "@/components/fixes/prepare-step";
import type { FixPlanStep } from "@/lib/types";

export const dynamic = "force-dynamic";

// Top fixes: the plan a team WORKS from. The order and the grouping are the server's (the same ones
// the VAPT report's roadmap and the bulk-PR engine use) — nothing here re-sorts or re-groups, or the
// page, the report and the pull requests would describe different work.
export default async function FixesPage() {
  const plan = await api.fixPlan();

  return (
    <div className="space-y-5">
      <PageIntro
        icon={ListOrdered}
        title="Top fixes"
        description="The work, in the order to do it. Each step is one change — an upgrade, a configuration fix, a code pattern — and it closes every finding it lists, in every repository and asset it touches."
      />

      <PageTabs tabs={SECURITY_TABS} />

      {plan.steps.length === 0 ? (
        <Empty>
          Nothing open to fix. When a scan finds something, it appears here grouped into the changes that close it.
        </Empty>
      ) : (
        <>
          <div className="flex flex-wrap gap-4 text-sm text-muted">
            <span>
              <span className="font-medium text-ink">{plan.open_findings}</span> open findings in{" "}
              <span className="font-medium text-ink">{plan.steps.length}</span> changes
            </span>
            {plan.ignored > 0 && (
              <span>
                <span className="font-medium text-ink">{plan.ignored}</span> held back by a risk decision
              </span>
            )}
          </div>

          {/* Verbatim: it carries why there are no effort estimates and why a delivered fix stays listed. */}
          <p className="text-xs text-subtle">{plan.note}</p>

          <ol className="space-y-3">
            {plan.steps.map((s) => (
              <StepCard key={s.key} step={s} />
            ))}
          </ol>
        </>
      )}
    </div>
  );
}

function StepCard({ step: s }: { step: FixPlanStep }) {
  const spread = s.assets.length;
  return (
    <li className="card space-y-2 px-4 py-3 text-sm">
      <div className="flex items-start gap-3">
        <span className="mono mt-0.5 w-6 shrink-0 text-right text-faint">{s.order}.</span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={s.severity} />
            <span className="font-medium text-ink">{s.title}</span>
          </div>
          <p className="text-muted">{s.action}</p>
          <p className="text-xs text-muted">
            Closes <span className="font-medium text-ink">{s.closes}</span> {s.closes === 1 ? "finding" : "findings"}
            {spread > 0 && (
              <>
                {" "}across <span className="font-medium text-ink">{spread}</span> {spread === 1 ? "asset" : "assets"}
              </>
            )}
            {s.unattributed > 0 && <> · {s.unattributed} we could not tie to an asset</>}
          </p>
          {s.validate && (
            <p className="text-xs text-medium">
              Unconfirmed — no tool proved this one. Check it is real before working on it.
            </p>
          )}
          {s.why && s.why.length > 0 && (
            <p className="text-[11px] leading-relaxed text-muted">
              <span className="font-medium text-ink/80">Why here:</span> {s.why.join(" · ")}
            </p>
          )}
          {spread > 0 && (
            <ul className="flex flex-wrap gap-1.5 pt-1">
              {s.assets.map((a) => (
                <li key={a.id} className="rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted">
                  <span className="mono text-ink/80">{a.target}</span> · {a.findings} ·{" "}
                  {a.owner ? a.owner : <span className="text-high">unowned</span>}
                </li>
              ))}
            </ul>
          )}
          <StepState step={s} />
        </div>
        {s.state.not_proposed > 0 && <PrepareStep stepKey={s.key} count={s.state.not_proposed} />}
      </div>
    </li>
  );
}

// Where the step stands at the desk. "Delivered" is deliberately not "done": the step stays on this
// plan until a scan no longer finds it, and a fix the re-scan contradicted says so in the urgent colour.
function StepState({ step: s }: { step: FixPlanStep }) {
  const st = s.state;
  const parts: { text: string; tone: string }[] = [];
  if (st.fix_did_not_hold > 0) parts.push({ text: `${st.fix_did_not_hold} fix did not hold — a re-scan still finds it`, tone: "text-high" });
  if (st.awaiting_approval > 0) parts.push({ text: `${st.awaiting_approval} waiting for your approval`, tone: "text-accent" });
  if (st.delivered > 0) parts.push({ text: `${st.delivered} delivered — the next scan confirms whether it worked`, tone: "text-muted" });
  if (st.declined > 0) parts.push({ text: `${st.declined} declined at the desk`, tone: "text-muted" });
  if (parts.length === 0) return null;
  return (
    <p className="text-[11px]">
      {parts.map((p, i) => (
        <span key={p.text} className={p.tone}>
          {i > 0 ? " · " : ""}
          {p.text}
        </span>
      ))}
    </p>
  );
}
