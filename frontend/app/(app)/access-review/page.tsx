import Link from "next/link";
import { UserCheck, CheckCircle2, ShieldMinus, Clock } from "lucide-react";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/components/ui/primitives";
import { PageIntro } from "@/components/ui/page-intro";
import { PageTabs } from "@/components/ui/page-tabs";
import { COMPLIANCE_TABS } from "@/lib/tabs";
import { DecideAccess } from "@/components/access-review/decide-access";
import { timeAgo } from "@/lib/utils";

export const dynamic = "force-dynamic";

// The periodic access review — SOC 2 CC6.2/CC6.3, the question an auditor asks that no scanner can
// answer: not "can you detect stale access", but "did a named person review who has access, and
// record what they decided".
//
// THREE THINGS THIS PAGE MUST NOT DO, each of which is why a field below is rendered rather than
// summarised:
//
//   1. Never present an EMPTY campaign as a completed review. `progress.complete` is false for a
//      campaign with nobody in it, and `detail` is the server's own sentence saying so. Rendered
//      verbatim, because "0 of 0" and "12 of 12" both read as done to someone skimming.
//   2. Never let a partly-answered review look finished. `pending` is shown as its own number, and
//      the completion banner is gated on the server's flag, not on our arithmetic.
//   3. Never imply that recording "remove" removed anything. The reviewer's verdict is an
//      attestation; the change goes through the approval desk like every other change.
export default async function AccessReviewPage() {
  const [review, me] = await Promise.all([api.accessReview(), api.me()]);
  const p = review.progress;
  const reviewer = me?.email ?? "";

  const pending = review.identities.filter((i) => !i.decision);
  const answered = review.identities.filter((i) => i.decision);

  return (
    <div className="space-y-6">
      <PageTabs tabs={COMPLIANCE_TABS} />
      <PageIntro
        icon={UserCheck}
        title="Access review"
        description="Every quarter an auditor asks not whether you can detect stale access, but whether a named person reviewed who has it and recorded what they decided. This is that review: the accounts your identity provider flagged, each with the reason it was flagged, waiting for a keep-or-remove answer."
      />

      <div className="card flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <Stat n={p.total} label="Under review" />
        <Stat n={p.pending} label="Awaiting a decision" cls="text-accent" />
        <Stat n={p.keep} label="Kept" cls="text-pulse" />
        <Stat n={p.revoke} label="Marked for removal" cls="text-high" />
        <div className="ml-auto flex items-center gap-2 text-sm">
          {p.complete ? (
            <>
              <CheckCircle2 className="h-4 w-4 text-pulse" />
              <span className="text-ink">Review complete</span>
            </>
          ) : (
            <>
              <Clock className="h-4 w-4 text-muted" />
              <span className="text-muted">Not complete</span>
            </>
          )}
        </div>
      </div>

      {/* The server's own words about what those numbers mean. This is the line that keeps an empty
          campaign from being filed as a completed access review. */}
      <p className="text-sm text-muted">{review.detail}</p>

      {p.total === 0 ? (
        <Empty>
          Nothing to review yet. Connect Google Workspace, Microsoft 365 or Okta under{" "}
          <Link href="/assets" className="text-accent hover:underline">
            Connections
          </Link>{" "}
          and the accounts that need an answer — stale, over-privileged, admin-without-MFA, or
          suspended but still holding a role — appear here after the next pass.
        </Empty>
      ) : (
        <div className="space-y-6">
          {pending.length > 0 && (
            <section className="space-y-2">
              <h2 className="text-xs font-medium uppercase tracking-wider text-muted">
                Awaiting a decision
              </h2>
              <ul className="space-y-2">
                {pending.map((i) => (
                  <Row key={i.subject} i={i} reviewer={reviewer} />
                ))}
              </ul>
            </section>
          )}

          {answered.length > 0 && (
            <section className="space-y-2">
              <h2 className="text-xs font-medium uppercase tracking-wider text-muted">Reviewed</h2>
              <ul className="space-y-2">
                {answered.map((i) => (
                  <Row key={i.subject} i={i} reviewer={reviewer} />
                ))}
              </ul>
            </section>
          )}

          {(review.revocations?.length ?? 0) > 0 && (
            <section className="rounded-2xl border border-high/30 bg-high/5 px-5 py-4">
              <div className="flex items-center gap-2 text-sm font-medium text-ink">
                <ShieldMinus className="h-4 w-4 text-high" />
                {review.revocations!.length} marked for removal
              </div>
              <p className="mt-1 text-sm text-muted">
                These decisions are recorded as evidence. They have not removed anyone — the removal
                is a change, and identity changes we can make are proposed for approval in the{" "}
                <Link href="/inbox" className="text-accent hover:underline">
                  Inbox
                </Link>{" "}
                like every other change.
              </p>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

function Row({
  i,
  reviewer,
}: {
  i: Awaited<ReturnType<typeof api.accessReview>>["identities"][number];
  reviewer: string;
}) {
  return (
    <li className="card px-5 py-4">
      <div className="flex flex-wrap items-start gap-3">
        <SeverityBadge severity={i.severity} />
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium text-ink">{i.subject}</div>
          {/* The reasons ARE the review. A reviewer answering without them is guessing, not
              reviewing — which is why the campaign carries them per account. */}
          <ul className="mt-1 space-y-0.5 text-sm text-muted">
            {i.reasons.map((r, n) => (
              <li key={n}>· {r}</li>
            ))}
          </ul>
          {i.decision && (
            <p className="mt-2 text-xs text-faint">
              {i.decision === "keep" ? "Kept" : "Marked for removal"} by{" "}
              <span className="text-muted">{i.decided_by || "—"}</span>
              {i.decided_at ? ` · ${timeAgo(i.decided_at)}` : ""}
              {i.note ? ` · "${i.note}"` : ""}
            </p>
          )}
        </div>
        <DecideAccess subject={i.subject} decision={i.decision} reviewer={reviewer} />
      </div>
    </li>
  );
}

function Stat({ n, label, cls = "text-ink" }: { n: number; label: string; cls?: string }) {
  return (
    <div>
      <div className={`text-xl font-semibold ${cls}`}>{n}</div>
      <div className="text-[11px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}
