"use client";

import { useState, useTransition } from "react";
import { Loader2, Unplug } from "lucide-react";
import { disconnectConnection } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

// DisconnectButton — the founder self-serve fix for a wrong/stale connection. Two-step (click →
// confirm) so it's never a one-tap mistake, then drives the tenant-scoped, ledger-signed
// disconnectConnection server action; the row disappears on success (revalidatePath). Errors surface
// inline rather than throwing.
export function DisconnectButton({ id, label }: { id: string; label: string }) {
  const [confirming, setConfirming] = useState(false);
  const [pending, start] = useTransition();
  const [error, setError] = useState("");

  function run() {
    setError("");
    start(async () => {
      const r = await disconnectConnection(id);
      if (!r.ok) {
        setError(r.error ?? "Failed");
        setConfirming(false);
      }
      // On success the server action revalidates /assets and this row is removed from the list.
    });
  }

  if (error) {
    return <span className="text-[11px] text-critical" title={error}>Couldn&apos;t disconnect</span>;
  }

  if (pending) {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-muted">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> Disconnecting…
      </span>
    );
  }

  if (confirming) {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px]">
        <span className="text-muted">Disconnect {label}?</span>
        <button onClick={run} className="font-medium text-critical hover:underline">Yes</button>
        <button onClick={() => setConfirming(false)} className="text-faint hover:text-ink">No</button>
      </span>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      title={`Disconnect ${label}`}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-faint transition",
        "hover:border-critical/40 hover:text-critical",
      )}
    >
      <Unplug className="h-3.5 w-3.5" /> Disconnect
    </button>
  );
}
