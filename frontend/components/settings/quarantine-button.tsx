"use client";

import { useState, useTransition } from "react";
import { ShieldOff, ShieldCheck, Loader2 } from "lucide-react";
import { setQuarantine } from "@/app/(app)/settings/actions";
import { cn } from "@/lib/utils";

// Per-connection quarantine toggle (WRD-4): the human freezes ONE connection's automation
// without halting the rest of the roster. Engaging asks to confirm; restoring is immediate.
export function QuarantineButton({ id, status }: { id: string; status: string }) {
  const [st, setSt] = useState(status);
  const [pending, start] = useTransition();
  const quarantined = st === "quarantined";

  function toggle() {
    const next = !quarantined;
    if (next && !window.confirm("Quarantine this connection? The agent stops scanning and acting through it until you restore it.")) {
      return;
    }
    start(async () => {
      const r = await setQuarantine(id, next);
      setSt(r.status);
    });
  }

  return (
    <button
      onClick={toggle}
      disabled={pending}
      title={quarantined ? "Restore automation for this connection" : "Freeze this connection's automation"}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition disabled:opacity-50",
        quarantined
          ? "border-pulse/40 bg-pulse/10 text-pulse hover:border-pulse"
          : "border-border text-muted hover:border-critical/40 hover:text-critical",
      )}
    >
      {pending ? (
        <Loader2 className="h-3 w-3 animate-spin" />
      ) : quarantined ? (
        <ShieldCheck className="h-3 w-3" />
      ) : (
        <ShieldOff className="h-3 w-3" />
      )}
      {quarantined ? "Restore" : "Quarantine"}
    </button>
  );
}
