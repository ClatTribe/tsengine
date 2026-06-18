import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { InboxClient } from "@/components/inbox/inbox-client";

export const dynamic = "force-dynamic";

export default async function InboxPage() {
  const [approvals, findings] = await Promise.all([api.approvals(), api.findings()]);
  const byId: Record<string, Finding> = {};
  for (const f of findings) byId[f.id] = f;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Inbox</h1>
          <p className="text-xs text-muted">Fixes the agent prepared and is holding for your decision.</p>
        </div>
        {approvals.length > 0 && (
          <span className="rounded-full border border-accent/30 bg-accent-soft px-2.5 py-1 text-xs text-accent">
            {approvals.length} awaiting
          </span>
        )}
      </div>
      <InboxClient actions={approvals} findings={byId} />
    </div>
  );
}
