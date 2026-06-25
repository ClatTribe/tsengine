"use client";

import { useState, useTransition } from "react";
import { ScanSearch, Loader2 } from "lucide-react";
import { syncGitHubPosture } from "@/app/(app)/settings/actions";

// Triggers the LIVE GitHub-org SaaS-posture sync (Bucket A) using the already-onboarded GitHub
// token — no posted snapshot. The resulting posture findings flow into Issues/Incidents.
export function GitHubPostureSync() {
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function run() {
    setErr("");
    setMsg("");
    start(async () => {
      try {
        const r = await syncGitHubPosture();
        setMsg(r.findings === 0 ? "No posture issues found" : `${r.findings} posture finding${r.findings === 1 ? "" : "s"} → Issues`);
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
        title="Run the SaaS-posture checks against your GitHub org using the connected token"
        className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
      >
        {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <ScanSearch className="h-3 w-3" />}
        Sync posture
      </button>
      {msg && <span className="ml-2 text-[11px] text-accent">{msg}</span>}
      {err && <span className="ml-2 text-[11px] text-critical">{err}</span>}
    </div>
  );
}
