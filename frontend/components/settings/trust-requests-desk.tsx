"use client";

import { useState, useTransition } from "react";
import { Inbox, Loader2, Copy, Check, Eye } from "lucide-react";
import { decideTrustRequest } from "@/app/(app)/settings/actions";
import type { TrustAccessRequest } from "@/lib/types";

// The owner's access desk: who asked for the gated documents, what was decided, and who has
// actually read them.
//
// Three things it is careful about:
//
//   - `granted` is the SERVER's answer, not `status === "approved"`. A request can be approved
//     and ungranted — expired, revoked, or the agreement still outstanding — and a desk that
//     showed "approved" for all of those would misreport who currently has access.
//   - An approval needs a NAME. The API refuses one without it, because a rule approving and a
//     person approving are different facts and the log has to distinguish them; an auto-approved
//     row is labelled as such rather than attributed to whoever happens to be looking.
//   - The access link is shown ONCE. Only its digest is stored, so if this is dismissed without
//     copying, the only remedy is to approve again.

function when(s?: string) {
  if (!s) return "";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

export function TrustRequestsDesk({
  requests,
  ndaRequired,
  me,
}: {
  requests: { request: TrustAccessRequest; granted: boolean; views: number }[];
  ndaRequired: boolean;
  me: string;
}) {
  const [pending, start] = useTransition();
  const [issued, setIssued] = useState<{ id: string; link: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState("");
  const [busyId, setBusyId] = useState("");

  function decide(id: string, decision: "approve" | "deny" | "revoke") {
    setErr("");
    setBusyId(id);
    start(async () => {
      try {
        const r = await decideTrustRequest(id, decision, me);
        if (r.access_link) setIssued({ id, link: r.access_link });
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed");
      } finally {
        setBusyId("");
      }
    });
  }

  const pendingCount = requests.filter((r) => r.request.status === "pending").length;

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Inbox className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Document access requests</div>
          <div className="text-xs text-muted">
            {pendingCount > 0 ? `${pendingCount} waiting on you` : "Nobody is waiting"}
          </div>
        </div>
      </div>

      {requests.length === 0 ? (
        <p className="mt-3 text-xs text-muted">
          No one has asked yet. Requests appear here the moment a buyer opens your Trust Center and asks for the
          gated documents.
        </p>
      ) : (
        <div className="mt-3 space-y-1.5">
          {requests.map(({ request: q, granted, views }) => (
            <div key={q.id} className="rounded-lg border border-border bg-surface p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs font-medium text-ink">
                    {q.name || q.email}
                    {q.company ? <span className="text-muted"> · {q.company}</span> : null}
                  </span>
                  <span className="mono block truncate text-[10px] text-faint">{q.email}</span>
                </span>

                {granted ? (
                  <span className="rounded-full bg-pulse-soft px-2 py-0.5 text-[10px] font-medium text-pulse">
                    Has access
                  </span>
                ) : q.status === "approved" ? (
                  // Approved but not granted — say WHICH, because the two need different action:
                  // one is waiting on the buyer, the others are finished.
                  <span className="rounded-full bg-surface-3 px-2 py-0.5 text-[10px] font-medium text-muted">
                    {q.revoked
                      ? "Revoked"
                      : ndaRequired && !q.nda_accepted_at
                        ? "Waiting on their signature"
                        : "Expired"}
                  </span>
                ) : (
                  <span className="rounded-full bg-surface-3 px-2 py-0.5 text-[10px] font-medium text-muted">
                    {q.status === "denied" ? "Denied" : "Pending"}
                  </span>
                )}

                {q.status === "pending" && (
                  <span className="flex gap-1.5">
                    <button
                      onClick={() => decide(q.id, "approve")}
                      disabled={pending}
                      className="inline-flex items-center gap-1 rounded-lg bg-accent px-2 py-1 text-[11px] font-semibold text-white transition hover:bg-accent-hover disabled:opacity-60"
                    >
                      {busyId === q.id && pending ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
                      Approve
                    </button>
                    <button
                      onClick={() => decide(q.id, "deny")}
                      disabled={pending}
                      className="rounded-lg border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-high/40 hover:text-high disabled:opacity-60"
                    >
                      Deny
                    </button>
                  </span>
                )}
                {granted && (
                  <button
                    onClick={() => decide(q.id, "revoke")}
                    disabled={pending}
                    className="rounded-lg border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-high/40 hover:text-high disabled:opacity-60"
                  >
                    Revoke
                  </button>
                )}
              </div>

              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-faint">
                <span>asked {when(q.requested_at)}</span>
                {q.auto_approved ? (
                  // Named as a rule's decision. Attributing it to a person would put a review in
                  // the log that nobody performed.
                  <span>approved by a domain rule</span>
                ) : q.decided_by ? (
                  <span>decided by {q.decided_by}</span>
                ) : null}
                {q.nda_accepted_at && <span>signed by {q.nda_name || "them"} {when(q.nda_accepted_at)}</span>}
                {q.expires_at && !q.revoked && <span>expires {when(q.expires_at)}</span>}
                {views > 0 && (
                  <span className="inline-flex items-center gap-1 text-muted">
                    <Eye className="h-3 w-3" /> opened {views}×
                  </span>
                )}
              </div>

              {issued?.id === q.id && (
                <div className="mt-2 rounded-lg border border-accent/30 bg-accent-soft/30 p-2">
                  <div className="text-[11px] font-semibold text-ink">Send them this link</div>
                  <div className="mono mt-1 overflow-x-auto whitespace-nowrap text-[10px] text-muted">{issued.link}</div>
                  <button
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(issued.link);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 1500);
                      } catch {
                        /* clipboard blocked — the text above is selectable */
                      }
                    }}
                    className="mt-1.5 inline-flex items-center gap-1 rounded-lg border border-border bg-surface px-2 py-1 text-[10px] font-medium text-muted transition hover:text-ink"
                  >
                    {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />} {copied ? "Copied" : "Copy"}
                  </button>
                  <p className="mt-1 text-[10px] text-faint">
                    Shown once — we store only a fingerprint of it. If you lose it, approve again.
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {err && <p className="mt-2 text-[11px] text-high">{err}</p>}
    </div>
  );
}
