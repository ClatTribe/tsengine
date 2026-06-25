import { Bug } from "lucide-react";
import { api } from "@/lib/api";
import { FindingsTable } from "@/components/findings/findings-table";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

export default async function FindingsPage() {
  // Join findings to the gated actions so the table can show what the agent is doing about
  // each one (a queued fix awaiting your approval) — not just a static list of problems.
  const [findings, approvals] = await Promise.all([api.findings(), api.approvals()]);
  const pendingByFinding = Array.from(new Set(approvals.map((a) => a.finding_id).filter(Boolean)));

  return (
    <div className="space-y-4">
      <PageIntro
        icon={Bug}
        title="Findings"
        description="The raw, detailed list of every weakness the agent has detected across your stack — each one backed by tool evidence, ranked by real-world risk, and showing what the agent is already doing about it."
      />
      <FindingsTable findings={findings} pendingFindingIds={pendingByFinding} />
    </div>
  );
}
