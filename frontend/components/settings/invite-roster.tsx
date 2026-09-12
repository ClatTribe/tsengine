"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Users, Loader2, Copy, Check, AlertTriangle } from "lucide-react";

// Seat everyone on the HRIS roster as an EMPLOYEE in one act — the training programme is unusable
// at any real size otherwise (forty people is forty invite forms).
//
// THREE THINGS THIS PANEL MUST NOT DO:
//   1. Never seat anyone from a click on a number. The owner sees the PLAN first — who would be
//      invited, who already has a seat, who is skipped and why — and confirms it.
//   2. Never fold the people who were NOT invited into a count. `skipped` and `already_seated` are
//      rendered by name with the server's reason; "38 invited" from a roster of 40 is only honest
//      when the two are named.
//   3. Never offer a role. The server mints employee seats only, and there is no control here to ask
//      for anything else — a bulk act must not be able to hand the whole company the security estate.
//
// The credentials follow the single invite's rule: mailed and not shown when SMTP is configured;
// otherwise shown ONCE, here, for the owner to relay.

type Seat = { email?: string; name?: string; department?: string; role?: string; reason?: string; hris_id?: string };
type Plan = {
  roster: number;
  no_roster: boolean;
  mailer: boolean;
  to_invite: Seat[];
  remaining: number;
  already_seated: Seat[];
  skipped: Seat[];
  detail: string;
};
type Invited = { email: string; name?: string; emailed: boolean; temp_password?: string };
type Result = Plan & { invited: Invited[]; failed: Seat[]; note: string };

export function InviteRoster() {
  const router = useRouter();
  const [plan, setPlan] = useState<Plan | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState<"plan" | "run" | "">("");
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState("");

  async function preview() {
    setBusy("plan");
    setErr("");
    setResult(null);
    const res = await fetch("/api/team/invite-roster", { cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    if (res.ok) setPlan(data);
    else setErr(data.error ?? "Could not read the roster.");
    setBusy("");
  }

  async function run() {
    setBusy("run");
    setErr("");
    const res = await fetch("/api/team/invite-roster", { method: "POST" });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setResult(data);
      setPlan(null);
      router.refresh();
    } else {
      setErr(data.error ?? "Roster invite failed.");
    }
    setBusy("");
  }

  function copy(text: string, key: string) {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(""), 1500);
  }

  return (
    <div className="space-y-3 border-t border-border px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium text-ink">Invite everyone on the HRIS roster</div>
          <p className="text-xs text-muted">
            Every active employee in your HR system gets an employee seat — their own security training
            and the policies to acknowledge, and nothing else. People who already have a seat are left as
            they are.
          </p>
        </div>
        {!plan && !result && (
          <button
            onClick={preview}
            disabled={busy !== ""}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-60"
          >
            {busy === "plan" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Users className="h-3.5 w-3.5" />}
            See who would be invited
          </button>
        )}
      </div>

      {err && <p className="text-xs text-critical">{err}</p>}

      {plan && (
        <div className="space-y-3 rounded-xl border border-border bg-surface-2 px-4 py-3">
          {/* The server's own sentence — it carries the refusals (empty roster, bounded run, how the
              credential travels) and this panel does not paraphrase it. */}
          <p className="text-sm text-ink">{plan.detail}</p>

          {plan.to_invite.length > 0 && (
            <SeatList title={`Would be invited (${plan.to_invite.length})`} seats={plan.to_invite} />
          )}
          {plan.already_seated.length > 0 && (
            <SeatList title={`Already have a seat (${plan.already_seated.length}) — untouched`} seats={plan.already_seated} showRole />
          )}
          {plan.skipped.length > 0 && (
            <SeatList title={`Skipped (${plan.skipped.length})`} seats={plan.skipped} showReason />
          )}

          <div className="flex items-center gap-2">
            {plan.to_invite.length > 0 && !plan.no_roster && (
              <button
                onClick={run}
                disabled={busy !== ""}
                className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-white transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60"
              >
                {busy === "run" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Users className="h-3.5 w-3.5" />}
                Invite {plan.to_invite.length} as employees
              </button>
            )}
            <button type="button" onClick={() => setPlan(null)} className="text-xs text-muted hover:text-ink">
              Cancel
            </button>
          </div>
        </div>
      )}

      {result && (
        <div className="space-y-3 rounded-xl border border-pulse/30 bg-pulse-soft/40 px-4 py-3">
          <p className="text-sm text-ink">{result.note}</p>

          {result.invited.some((i) => !i.emailed) && (
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-medium text-high">
                <AlertTriangle className="h-3.5 w-3.5" /> One-time passwords — shown once, relay each securely
              </div>
              <ul className="space-y-1">
                {result.invited.filter((i) => !i.emailed).map((i) => (
                  <li key={i.email} className="flex items-center gap-2 text-xs">
                    <span className="w-56 truncate text-muted">{i.name ? `${i.name} · ` : ""}{i.email}</span>
                    <code className="mono flex-1 truncate rounded-lg border border-border bg-surface px-2 py-1">{i.temp_password}</code>
                    <button
                      onClick={() => copy(i.temp_password ?? "", i.email)}
                      className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-border bg-surface text-muted transition hover:text-ink"
                      aria-label={`Copy password for ${i.email}`}
                    >
                      {copied === i.email ? <Check className="h-3.5 w-3.5 text-pulse" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </li>
                ))}
              </ul>
              <button
                onClick={() =>
                  copy(
                    result.invited.filter((i) => !i.emailed).map((i) => `${i.email}\t${i.temp_password}`).join("\n"),
                    "all",
                  )
                }
                className="text-xs text-accent hover:underline"
              >
                {copied === "all" ? "Copied all" : "Copy all as email ⇥ password"}
              </button>
            </div>
          )}

          {result.invited.some((i) => i.emailed) && (
            <SeatList
              title={`Emailed an invite (${result.invited.filter((i) => i.emailed).length})`}
              seats={result.invited.filter((i) => i.emailed)}
            />
          )}
          {result.failed.length > 0 && <SeatList title={`Failed (${result.failed.length})`} seats={result.failed} showReason tone="text-critical" />}
          {result.already_seated.length > 0 && (
            <SeatList title={`Already had a seat (${result.already_seated.length})`} seats={result.already_seated} showRole />
          )}
          {result.skipped.length > 0 && <SeatList title={`Skipped (${result.skipped.length})`} seats={result.skipped} showReason />}

          <button type="button" onClick={() => setResult(null)} className="text-xs text-muted hover:text-ink">
            Done
          </button>
        </div>
      )}
    </div>
  );
}

function SeatList({
  title,
  seats,
  showRole,
  showReason,
  tone = "text-muted",
}: {
  title: string;
  seats: Seat[];
  showRole?: boolean;
  showReason?: boolean;
  tone?: string;
}) {
  return (
    <div>
      <div className={`text-[11px] font-medium uppercase tracking-wider ${tone}`}>{title}</div>
      <ul className="mt-1 space-y-0.5">
        {seats.map((s, i) => (
          <li key={`${s.email ?? ""}${s.hris_id ?? ""}${i}`} className="flex flex-wrap items-baseline gap-x-2 text-xs">
            <span className="text-ink">{s.name || s.email || s.hris_id}</span>
            {s.name && s.email && <span className="text-faint">{s.email}</span>}
            {!s.email && s.hris_id && <span className="text-faint">HRIS id {s.hris_id}</span>}
            {s.department && <span className="text-faint">· {s.department}</span>}
            {showRole && s.role && <span className="text-faint">· {s.role}</span>}
            {showReason && s.reason && <span className="text-muted">— {s.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
