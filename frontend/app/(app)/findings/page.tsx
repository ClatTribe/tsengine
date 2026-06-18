import { api } from "@/lib/api";
import { FindingsTable } from "@/components/findings/findings-table";

export const dynamic = "force-dynamic";

export default async function FindingsPage() {
  const findings = await api.findings();
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Findings</h1>
        <p className="text-xs text-muted">Everything the agent detected — grounded, prioritized, exportable.</p>
      </div>
      <FindingsTable findings={findings} />
    </div>
  );
}
