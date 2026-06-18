"use client";

import { useState, useTransition } from "react";
import { RefreshCw, Check } from "lucide-react";
import { rescanAll } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

// "Scan now" — manual trigger over RescanTenant. Optimistic spinner; on success it flashes
// the count of assets scanned, then settles back.
export function ScanNow({ disabled }: { disabled?: boolean }) {
  const [pending, start] = useTransition();
  const [done, setDone] = useState<number | null>(null);

  function run() {
    setDone(null);
    start(async () => {
      const { scanned } = await rescanAll();
      setDone(scanned);
      setTimeout(() => setDone(null), 4000);
    });
  }

  return (
    <button
      onClick={run}
      disabled={pending || disabled}
      className={cn(
        "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50",
        done != null
          ? "border-pulse/40 bg-pulse/10 text-pulse"
          : "border-accent/40 bg-accent-soft text-accent hover:border-accent",
      )}
    >
      {done != null ? (
        <>
          <Check className="h-3.5 w-3.5" /> Scanned {done} {done === 1 ? "asset" : "assets"}
        </>
      ) : (
        <>
          <RefreshCw className={cn("h-3.5 w-3.5", pending && "animate-spin")} />
          {pending ? "Scanning…" : "Scan now"}
        </>
      )}
    </button>
  );
}
