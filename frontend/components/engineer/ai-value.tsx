import type { AIValue } from "@/lib/types";

// What the AI cost, against what it proved — per surface, last 30 days.
//
// Three refusals, each the server's and rendered as given: a surface with any run whose cost is unknown
// shows no cost-per-proof (dividing a partial cost by the whole outcome flatters the AI); the outcome is
// findings the runs themselves VERIFIED, not findings they mentioned; and fixes proven closed are shown as
// context, never credited to the AI, because the fix may have come from anywhere.

const LABEL: Record<string, string> = {
  estate: "Whole-estate reviews",
  issue: "Issue investigations",
  cloud: "Cloud",
  code: "Code",
  pentest: "AI Pentester",
  compliance: "Compliance",
  eval: "Your eval suite",
  other: "Other AI work",
};
const usd = (n: number) => `$${n.toFixed(2)}`;

export function AIValueCard({ v }: { v: AIValue }) {
  if (v.total.runs === 0 && v.total.calls === 0) {
    return (
      <div className="card p-4 text-xs text-muted">
        No AI runs in the last {v.days} days, so there is nothing to weigh yet.
      </div>
    );
  }
  return (
    <div className="card space-y-3 p-4">
      <div className="text-sm font-medium text-ink">What the AI cost, and what it proved — last {v.days} days</div>
      <table className="w-full text-xs">
        <thead className="text-faint">
          <tr>
            <th className="text-left font-medium">Surface</th>
            <th className="text-right font-medium">Runs</th>
            <th className="text-right font-medium">Spent</th>
            <th className="text-right font-medium">Proven findings</th>
            <th className="text-right font-medium">Cost per proof</th>
          </tr>
        </thead>
        <tbody>
          {[...v.surfaces, v.total].map((s) => (
            <tr key={s.surface} className={s.surface === "all" ? "border-t border-border font-medium" : ""}>
              <td className="py-1">{s.surface === "all" ? "Total" : (LABEL[s.surface] ?? s.surface)}</td>
              <td className="text-right">
                {s.runs}
                {s.calls > 0 && <span className="text-faint"> + {s.calls} model calls</span>}
              </td>
              <td className="text-right">
                {usd(s.usd)}
                {s.unknown_cost_runs + s.unknown_cost_calls > 0 && (
                  <span className="text-faint"> + {s.unknown_cost_runs + s.unknown_cost_calls} unpriced</span>
                )}
              </td>
              <td className="text-right">{s.verified}</td>
              <td className="text-right">
                {s.cost_per_verified !== undefined ? usd(s.cost_per_verified) : <span className="text-faint">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-[11px] text-faint">
        &ldquo;Model calls&rdquo; are single requests made outside a priced run — a code sweep, exploit proposals, CWE
        attribution — and count toward your monthly AI budget like runs do. &ldquo;Unpriced&rdquo; runs or calls used a
        model that reported no usage — their cost is unknown, not zero, so cost per proof
        is not shown where they occur. {v.fixes_proven_closed} fix(es) were proven closed by a re-test in this period;
        that is shown for context and not credited to the AI.
        {v.unmetered.length > 0 && <> Not yet counted here: {v.unmetered.join(", ")}.</>}
      </p>
    </div>
  );
}
