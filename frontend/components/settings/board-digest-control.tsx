"use client";

import { useState, useTransition } from "react";
import { FileBarChart, Loader2, Send } from "lucide-react";
import { setBoardDigest, sendBoardDigestNow } from "@/app/(app)/settings/actions";
import type { BoardDigestSettings, User } from "@/lib/types";

// The board report, emailed on a schedule.
//
// Recipients are PICKED from the people who hold a seat — there is no box to type an address into,
// because the report lists exposure that is exploitable today and the server refuses anyone without a
// seat. An auditor seat is the read-only way to give a board member access. Whether anything will actually
// be sent is the server's statement (delivery_configured / delivery_note), rendered as given: a saved
// schedule on a deployment with no mail relay must not read as a working one. The last delivery problem
// is shown too, so "the board stopped getting it" is visible here rather than discovered at the meeting.

const fmt = (s?: string) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "");

export function BoardDigestControl({
  initial,
  members,
  canManage,
}: {
  initial: BoardDigestSettings;
  members: User[];
  canManage: boolean;
}) {
  const [s, setS] = useState(initial);
  const [cadence, setCadence] = useState<"weekly" | "monthly">(initial.cadence ?? "monthly");
  const [picked, setPicked] = useState<Set<string>>(new Set(initial.recipients));
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  const seats = members.filter((m) => m.email);

  function toggle(email: string) {
    setPicked((p) => {
      const n = new Set(p);
      if (n.has(email)) n.delete(email);
      else n.add(email);
      return n;
    });
  }

  function save(enabled: boolean) {
    setErr("");
    start(async () => {
      try {
        setS(await setBoardDigest({ enabled, cadence, recipients: [...picked] }));
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  function sendNow() {
    setErr("");
    start(async () => {
      try {
        setS(await sendBoardDigestNow());
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to send");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3 space-y-2.5">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <FileBarChart className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Board report by email</div>
          <div className="text-xs text-muted">
            {s.enabled
              ? `Sent ${s.cadence} to ${s.recipients.length} person(s)${s.next_due ? ` · next ${fmt(s.next_due)}` : " · next on the coming monitoring pass"}`
              : "Off. The report is on the Board page whenever you want it."}
          </div>
        </div>
      </div>

      {s.delivery_note && (
        <p className="rounded-lg border border-medium/30 bg-medium/5 px-3 py-2 text-xs text-ink">{s.delivery_note}</p>
      )}
      {s.last_sent_at && <p className="text-xs text-muted">Last delivered {fmt(s.last_sent_at)}.</p>}
      {s.last_error && (
        <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">
          Last attempt {fmt(s.last_attempt_at)}: {s.last_error}
        </p>
      )}

      {canManage && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-muted">Every</span>
            <select
              value={cadence}
              onChange={(e) => setCadence(e.target.value as "weekly" | "monthly")}
              className="rounded-lg border border-border bg-surface px-2 py-1 text-xs"
            >
              <option value="weekly">week</option>
              <option value="monthly">month</option>
            </select>
          </div>
          <div className="text-xs text-muted">
            Send to (people with a seat — invite a board member as an auditor for read-only access):
          </div>
          <ul className="space-y-1">
            {seats.map((m) => (
              <li key={m.email}>
                <label className="flex items-center gap-2 text-xs text-ink">
                  <input type="checkbox" checked={picked.has(m.email)} onChange={() => toggle(m.email)} />
                  {m.email} <span className="text-faint">({m.role})</span>
                </label>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={pending || picked.size === 0}
              onClick={() => save(true)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60"
            >
              {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />} {s.enabled ? "Save schedule" : "Turn on"}
            </button>
            {s.enabled && (
              <>
                <button
                  type="button"
                  disabled={pending || !s.delivery_configured}
                  onClick={sendNow}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink disabled:opacity-60"
                >
                  <Send className="h-3.5 w-3.5" /> Send now
                </button>
                <button
                  type="button"
                  disabled={pending}
                  onClick={() => save(false)}
                  className="rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-ink disabled:opacity-60"
                >
                  Turn off
                </button>
              </>
            )}
          </div>
        </div>
      )}
      {err && <p className="rounded-lg border border-critical/30 bg-critical/5 px-3 py-2 text-xs text-critical">{err}</p>}
    </div>
  );
}
