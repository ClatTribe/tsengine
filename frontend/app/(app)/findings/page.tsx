import { api } from "@/lib/api";
import { FindingsTable } from "@/components/findings/findings-table";

export const dynamic = "force-dynamic";

export default async function FindingsPage() {
  // Join findings to the gated actions so the table can show what the agent is doing about
  // each one (a queued fix awaiting your approval) — not just a static list of problems.
  const [findings, approvals] = await Promise.all([api.findings(), api.approvals()]);
  const pendingByFinding = Array.from(new Set(approvals.map((a) => a.finding_id).filter(Boolean)));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Findings</h1>
        <p className="text-xs text-muted">Everything the agent detected — grounded, prioritized, and acted on.</p>
      </div>
      <FindingsTable findings={findings} pendingFindingIds={pendingByFinding} />
    </div>
  );
}
