"use client";

import { useState, useTransition } from "react";
import { Radar, Check, CircleAlert } from "lucide-react";
import { runOsintScan } from "@/app/(app)/osint/actions";
import { cn } from "@/lib/utils";

// "Run OSINT scan" — triggers the live, keyless Certificate-Transparency collection (crt.sh) over the
// tenant's domains. No API key. Flashes the discovery result, then settles.
export function RunOsintScan() {
  const [pending, start] = useTransition();
  const [res, setRes] = useState<{ ok: boolean; hosts?: number; findings?: number; error?: string } | null>(null);

  function run() {
    setRes(null);
    start(async () => {
      const r = await runOsintScan();
      setRes(r);
      setTimeout(() => setRes(null), 6000);
    });
  }

  return (
    <button
      onClick={run}
      disabled={pending}
      className={cn(
        "inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition disabled:opacity-50",
        res?.ok === false
          ? "border-critical/40 bg-critical/10 text-critical"
          : res?.ok
            ? "border-pulse/40 bg-pulse/10 text-pulse"
            : "border-accent/40 bg-accent-soft text-accent hover:border-accent",
      )}
      title="Live, keyless Certificate-Transparency scan over your domains"
    >
      {res?.ok ? (
        <>
          <Check className="h-3.5 w-3.5" />
          {res.findings ? `${res.findings} found` : `${res.hosts ?? 0} hosts`}
        </>
      ) : res?.ok === false ? (
        <>
          <CircleAlert className="h-3.5 w-3.5" /> Scan failed
        </>
      ) : (
        <>
          <Radar className={cn("h-3.5 w-3.5", pending && "animate-spin")} />
          {pending ? "Scanning…" : "Run OSINT scan"}
        </>
      )}
    </button>
  );
}
