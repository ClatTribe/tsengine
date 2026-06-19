import Link from "next/link";
import { UserCheck, CheckCircle2, Clock, Bug, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import type { ReviewRequest } from "@/lib/types";
import { Card, SectionTitle, Empty } from "@/components/ui/primitives";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function ReviewsPage() {
  const all = await api.reviews();
  const open = all.filter((r) => r.status !== "resolved").sort(byCreated);
  const resolved = all.filter((r) => r.status === "resolved").sort(byCreated);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-lg font-semibold">Expert reviews</h1>
          <p className="text-xs text-muted">Findings &amp; fixes you&apos;ve escalated for a human expert — the AI-plus-a-human safety net.</p>
        </div>
        {open.length > 0 && (
          <span className="rounded-full border border-accent/30 bg-accent-soft px-2.5 py-1 text-xs text-accent">{open.length} open</span>
        )}
      </div>

      <div>
        <SectionTitle>Awaiting an expert</SectionTitle>
        {open.length === 0 ? (
          <Empty>Nothing in review. Escalate any finding from its detail page to get an expert&apos;s eyes on it.</Empty>
        ) : (
          <div className="space-y-2">{open.map((r) => <ReviewRow key={r.id} r={r} />)}</div>
        )}
      </div>

      {resolved.length > 0 && (
        <div>
          <SectionTitle>Resolved</SectionTitle>
          <div className="space-y-2">{resolved.map((r) => <ReviewRow key={r.id} r={r} />)}</div>
        </div>
      )}
    </div>
  );
}

function byCreated(a: ReviewRequest, b: ReviewRequest) {
  return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
}

function ReviewRow({ r }: { r: ReviewRequest }) {
  const resolved = r.status === "resolved";
  const isFinding = r.subject === "finding";
  const SubjectIcon = isFinding ? Bug : Wrench;
  return (
    <Card className="p-4">
      <div className="flex items-start gap-3">
        <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${resolved ? "bg-pulse-soft text-pulse" : "bg-accent-soft text-accent"}`}>
          {resolved ? <CheckCircle2 className="h-4 w-4" /> : <UserCheck className="h-4 w-4" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 text-xs font-medium capitalize text-muted">
              <SubjectIcon className="h-3.5 w-3.5" /> {r.subject}
            </span>
            {isFinding ? (
              <Link href={`/findings/${r.subject_id}`} className="mono truncate text-xs text-accent hover:underline">{r.subject_id}</Link>
            ) : (
              <span className="mono truncate text-xs text-faint">{r.subject_id}</span>
            )}
          </div>
          {r.note && <p className="mt-1.5 text-sm text-ink">{r.note}</p>}
          {resolved && r.resolution && (
            <div className="mt-2 rounded-lg border border-border bg-surface-2 p-2.5 text-sm text-muted">
              <span className="font-medium text-ink">Resolution:</span> {r.resolution}
              {r.reviewer && <span className="text-faint"> — {r.reviewer}</span>}
            </div>
          )}
          <div className="mt-2 flex items-center gap-3 text-[11px] text-faint">
            <span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" /> requested {timeAgo(r.created_at)}</span>
            {r.requester && <span>by {r.requester}</span>}
            {resolved && r.resolved_at && <span className="text-pulse">resolved {timeAgo(r.resolved_at)}</span>}
          </div>
        </div>
      </div>
    </Card>
  );
}
