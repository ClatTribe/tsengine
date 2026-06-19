"use client";

import { useState, useTransition } from "react";
import { ShieldAlert, ShieldCheck, Loader2 } from "lucide-react";
import { setKillSwitch } from "@/app/(app)/settings/actions";
import { cn } from "@/lib/utils";

// The global kill-switch control (agentic-SMB spec OM-3 / TS-5) — the one human "on the
// loop" can freeze every agent instantly. Owner-gated. Engaging asks for confirmation
// (it pauses all automation); disengaging is immediate.
export function KillSwitch({ halted: initial, canToggle }: { halted: boolean; canToggle: boolean }) {
  const [halted, setHalted] = useState(initial);
  const [pending, start] = useTransition();

  function toggle() {
    const next = !halted;
    if (next && !window.confirm("Halt ALL automation? No scans or fixes will run until you resume. The dashboard stays readable.")) {
      return;
    }
    start(async () => {
      const r = await setKillSwitch(next);
      setHalted(r.halted);
    });
  }

  return (
    <div
      className={cn(
        "flex items-center justify-between gap-4 rounded-xl border px-4 py-3",
        halted ? "border-critical/40 bg-critical/5" : "border-border bg-surface",
      )}
    >
      <div className="flex items-start gap-3">
        {halted ? (
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-critical" />
        ) : (
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-pulse" />
        )}
        <div>
          <div className="text-sm font-medium">
            {halted ? "Automation halted" : "Automation active"}
          </div>
          <p className="mt-0.5 text-xs text-muted">
            {halted
              ? "All agent action is frozen — no scans, no fixes. Proposed actions queue until you resume."
              : "Agents scan continuously and queue fixes for your approval. The kill-switch freezes everything instantly."}
          </p>
        </div>
      </div>
      {canToggle ? (
        <button
          onClick={toggle}
          disabled={pending}
          className={cn(
            "inline-flex shrink-0 items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-semibold transition disabled:opacity-50",
            halted
              ? "border-pulse/40 bg-pulse/10 text-pulse hover:border-pulse"
              : "border-critical/40 bg-critical/5 text-critical hover:border-critical",
          )}
        >
          {pending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {halted ? "Resume automation" : "Halt all automation"}
        </button>
      ) : (
        <span className="shrink-0 text-[11px] text-faint">owner only</span>
      )}
    </div>
  );
}
