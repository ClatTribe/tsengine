"use client";

import { useState, useTransition } from "react";
import { setAutonomy } from "./actions";

// One button: allow or withdraw. The outcome is the server's, including its refusal text.
export function AutonomyToggle({ cls, remediationType, allow, label }: { cls: string; remediationType: string; allow: boolean; label: string }) {
  const [pending, start] = useTransition();
  const [err, setErr] = useState<string | null>(null);
  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        disabled={pending}
        className="rounded border border-border px-2 py-0.5 text-[11px] text-ink hover:border-accent disabled:opacity-50"
        onClick={() =>
          start(async () => {
            const r = await setAutonomy(cls, remediationType, allow);
            setErr(r.ok ? null : r.error);
          })
        }
      >
        {pending ? "Saving…" : label}
      </button>
      {err && <span className="text-[11px] text-high">{err}</span>}
    </span>
  );
}
