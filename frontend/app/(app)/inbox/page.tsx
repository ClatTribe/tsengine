import { Inbox } from "lucide-react";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { InboxClient } from "@/components/inbox/inbox-client";
import { PageIntro } from "@/components/ui/page-intro";

export const dynamic = "force-dynamic";

export default async function InboxPage() {
  const [approvals, findings] = await Promise.all([api.approvals(), api.findings()]);
  const byId: Record<string, Finding> = {};
  for (const f of findings) byId[f.id] = f;

  return (
    <div className="space-y-4">
      <PageIntro
        icon={Inbox}
        title="Inbox"
        description="Your approval queue. The agent prepares each fix and holds it here for your call — review the change, then approve or reject. Nothing consequential ships without your sign-off."
        right={
          approvals.length > 0 ? (
            <span className="rounded-full border border-accent/30 bg-accent-soft px-2.5 py-1 text-xs text-accent">
              {approvals.length} awaiting
            </span>
          ) : undefined
        }
      />
      <InboxClient actions={approvals} findings={byId} />
    </div>
  );
}
