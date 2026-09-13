"use client";

import { useState, useTransition } from "react";
import { ScanSearch, Loader2 } from "lucide-react";
import { syncOktaPosture } from "@/app/(app)/settings/actions";

// Triggers the LIVE Okta CONFIGURATION posture read — the org's sign-on, password and
// MFA-enrollment policies, its API tokens and ThreatInsight — through the onboarded token. The
// accounts half (who lacks MFA, who is a super admin) runs on every scan already; this is the
// policy half. Findings flow into Issues/Incidents.
//
// The unread count is rendered beside the finding count on purpose: a token without
// okta.policies.read reads NOTHING about the policies, and "0 posture issues" would then be a
// statement about the token, not the org.
export function OktaPostureSync() {
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function run() {
    setErr("");
    setMsg("");
    start(async () => {
      try {
        const r = await syncOktaPosture();
        const found = r.findings === 0 ? "No policy issues found" : `${r.findings} policy finding${r.findings === 1 ? "" : "s"} → Issues`;
        setMsg(r.unread > 0 ? `${found} · ${r.unread} setting${r.unread === 1 ? "" : "s"} could not be read` : found);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Sync failed");
      }
    });
  }

  return (
    <div className="mt-2 pl-11">
      <button
        onClick={run}
        disabled={pending}
        title="Read the org's sign-on, password and MFA-enrollment policies, API tokens and ThreatInsight through the connected token"
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <ScanSearch className="h-3 w-3" />}
        Sync policies
      </button>
      {msg && <span className="ml-2 text-[11px] text-accent">{msg}</span>}
      {err && <span className="ml-2 text-[11px] text-critical">{err}</span>}
    </div>
  );
}
