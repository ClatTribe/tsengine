import { Inbox } from "lucide-react";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { InboxClient } from "@/components/inbox/inbox-client";
import { PageIntro } from "@/components/ui/page-intro";
import { hitlOwner, capitalize } from "@/lib/service-model";

export const dynamic = "force-dynamic";

export default async function InboxPage() {
  const [approvals, findings, practitioners] = await Promise.all([
    api.approvals(),
    api.findings(),
    api.practitioners(),
  ]);
  const byId: Record<string, Finding> = {};
  for (const f of findings) byId[f.id] = f;

  // Service-model framing: a managed/MSP customer doesn't OWN these approvals — their expert does (via
  // the /operator console). Reframe the queue as informational ("handled by X, weigh in if you want")
  // instead of nagging them with an action-required to-do that isn't theirs.
  const { selfOwned, actor } = hitlOwner(practitioners?.service_model, practitioners?.practitioners?.[0]);

  const description = selfOwned
    ? "Your approval queue. The agent prepares each fix and holds it here for your call — review the change, then approve or reject. Nothing consequential ships without your sign-off."
    : `${capitalize(actor)} reviews and approves these fixes for you. This queue is here so you can see what's being handled and weigh in if you want — you don't have to act on it.`;

  return (
    <div className="space-y-4">
      <PageIntro
        icon={Inbox}
        title="Inbox"
        description={description}
        right={
          approvals.length > 0 ? (
            <span className="rounded-full border border-accent/30 bg-accent-soft px-2.5 py-1 text-xs text-accent">
              {approvals.length} {selfOwned ? "awaiting" : "in review"}
            </span>
          ) : undefined
        }
      />
      {!selfOwned && approvals.length > 0 && (
        <div className="rounded-lg border border-border bg-surface px-4 py-3 text-sm text-muted">
          {capitalize(actor)} is handling {approvals.length} {approvals.length === 1 ? "fix" : "fixes"}.
          You can review the detail and weigh in below, or leave it to your team.
        </div>
      )}
      <InboxClient actions={approvals} findings={byId} />
    </div>
  );
}
