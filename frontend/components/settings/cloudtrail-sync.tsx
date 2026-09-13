"use client";

import { useState, useTransition } from "react";
import { Radar, Loader2 } from "lucide-react";
import { syncCloudEvents } from "@/app/(app)/settings/actions";

// Triggers the LIVE CloudTrail poll — the account's control-plane events since the last read
// (root console login, a security group opened to the world, an admin policy attached, a trail
// stopped) through the connected read-only role. The same poll runs on every monitoring pass;
// this is the on-demand door. Threats flow into Issues/Incidents.
//
// The unread count is rendered beside the finding count on purpose: a busy account can write more
// events than one read examines, and "0 threats" over a partial window is a statement about the
// read, not the account.
export function CloudTrailSync() {
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function run() {
    setErr("");
    setMsg("");
    start(async () => {
      try {
        const r = await syncCloudEvents();
        const found = r.findings === 0
          ? `No control-plane threats in ${r.records} event${r.records === 1 ? "" : "s"}`
          : `${r.findings} threat${r.findings === 1 ? "" : "s"} in ${r.records} events → Incidents`;
        setMsg(r.unread > 0 ? `${found} · part of the window could not be read` : found);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Read failed");
      }
    });
  }

  return (
    <div className="mt-2 pl-11">
      <button
        onClick={run}
        disabled={pending}
        title="Read the account's CloudTrail events since the last pass through the connected role and run the CDR rules over them"
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Radar className="h-3 w-3" />}
        Read CloudTrail
      </button>
      {msg && <span className="ml-2 text-[11px] text-accent">{msg}</span>}
      {err && <span className="ml-2 text-[11px] text-critical">{err}</span>}
    </div>
  );
}
