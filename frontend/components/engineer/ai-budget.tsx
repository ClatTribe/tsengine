import type { AIBudgetPlan } from "@/lib/types";

// Where the next AI tokens should go — the capital-allocation PLAN (twin of the AI-value card, which
// shows what tokens BOUGHT). The allocator is grounded and spends nothing: a surface with no open
// exposure gets 0%, the basis states what each share rests on, and the notes name what it could not see
// (no budget, no model, issues it could not attribute). Rendered as the server computed it.

const LABEL: Record<string, string> = { cloud: "Cloud", code: "Code", web: "Web & API" };
const usd = (n: number) => `$${n.toFixed(0)}`;

export function AIBudgetCard({ p }: { p: AIBudgetPlan }) {
  const anyExposure = p.buckets.some((b) => b.exposure > 0);
  return (
    <div className="card space-y-3 p-4">
      <div className="text-sm font-medium text-ink">
        Where the next AI tokens should go
        {p.budget_set ? <span className="text-faint"> · {usd(p.monthly_budget_usd)}/mo budget</span> : null}
      </div>
      <div className="text-xs text-muted">
        Ranked by open, reachable exposure per surface, nudged by what tokens there have proved. A plan, not a cap — it spends nothing itself.
      </div>
      {anyExposure ? (
        <table className="w-full text-xs">
          <thead className="text-faint">
            <tr>
              <th className="text-left font-medium">Surface</th>
              <th className="text-right font-medium">Open</th>
              <th className="text-right font-medium">Exposure</th>
              <th className="text-right font-medium">Cost / proof</th>
              <th className="text-right font-medium">Share</th>
              {p.budget_set ? <th className="text-right font-medium">Recommended</th> : null}
              <th className="text-left font-medium pl-3">Basis</th>
            </tr>
          </thead>
          <tbody>
            {p.buckets.map((b) => (
              <tr key={b.surface} className={b.exposure === 0 ? "text-faint" : ""}>
                <td className="py-1">{LABEL[b.surface] ?? b.surface}</td>
                <td className="text-right">{b.open_issues}</td>
                <td className="text-right">{b.exposure}</td>
                <td className="text-right">{b.cost_per_verified != null ? `$${b.cost_per_verified.toFixed(2)}` : "—"}</td>
                <td className="text-right font-medium text-ink">{b.share_pct}%</td>
                {p.budget_set ? <td className="text-right">{b.recommended_usd ? usd(b.recommended_usd) : "—"}</td> : null}
                <td className="pl-3 text-faint">{b.basis}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="text-xs text-muted">No open exposure on any surface — nothing to allocate.</div>
      )}
      {p.notes.length > 0 ? (
        <ul className="space-y-1 text-xs text-faint">
          {p.notes.map((n, i) => (
            <li key={i}>· {n}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
