"use client";

import { useState, useTransition } from "react";
import { RefreshCw, Check, AlertTriangle } from "lucide-react";
import { rescanAll } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

// "Scan now" — manual trigger over RescanTenant. The platform queues the scan as a
// background job and returns immediately, so the button flashes "Scan started" (or the
// asset count, if the platform scanned synchronously), then settles back.
export function ScanNow({ disabled }: { disabled?: boolean }) {
  const [pending, start] = useTransition();
  const [done, setDone] = useState<{ scanned?: number; queued?: boolean; error?: string } | null>(null);

  function run() {
    setDone(null);
    start(async () => {
      const r = await rescanAll();
      setDone(r);
      // A refusal needs longer on screen than a success — the reader has to act on it.
      setTimeout(() => setDone(null), r.error ? 8000 : 4000);
    });
  }

  return (
    <button
      onClick={run}
      disabled={pending || disabled}
      className={cn(
        "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50",
        done?.error
          ? "border-critical/40 bg-critical/10 text-critical"
          : done
            ? "border-pulse/40 bg-pulse/10 text-pulse"
            : "border-accent/40 bg-accent-soft text-accent hover:border-accent",
      )}
    >
      {done?.error ? (
        <>
          <AlertTriangle className="h-3.5 w-3.5" />
          {done.error}
        </>
      ) : done ? (
        <>
          <Check className="h-3.5 w-3.5" />
          {done.queued ? "Scan started" : `Scanned ${done.scanned} ${done.scanned === 1 ? "asset" : "assets"}`}
        </>
      ) : (
        <>
          <RefreshCw className={cn("h-3.5 w-3.5", pending && "animate-spin")} />
          {pending ? "Starting…" : "Scan now"}
        </>
      )}
    </button>
  );
}
