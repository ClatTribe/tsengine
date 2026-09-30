"use client";

import { useTransition } from "react";
import { Loader2 } from "lucide-react";
import { setAssetEnvironment } from "@/app/(app)/assets/actions";
import { cn } from "@/lib/utils";

const ENVS = [
  { value: "production", label: "Production" },
  { value: "staging", label: "Staging" },
  { value: "development", label: "Development" },
] as const;

// EnvironmentSelect records where an asset lives. Unset is NOT blank-and-fine: the server's label says
// it is treated as production (the pentester will not attack it without a production authorization),
// and that label is rendered as given. A name-based suggestion is offered as a one-click CONFIRM, never
// applied on its own — "staging.acme.com" is a naming habit, not a fact.
export function EnvironmentSelect({ assetId, environment, label, suggested }: {
  assetId: string; environment: string; label?: string; suggested?: string;
}) {
  const [pending, start] = useTransition();
  const set = (v: string) => { if (v && v !== environment && !pending) start(() => setAssetEnvironment(assetId, v)); };
  return (
    <div className="inline-flex flex-wrap items-center gap-1.5 text-[11px]">
      <span className={cn("rounded-md border px-1.5 py-0.5 font-medium",
        environment ? "border-border bg-surface-2 text-muted" : "border-medium/30 bg-medium/10 text-medium")}>
        {pending ? <Loader2 className="inline h-3 w-3 animate-spin" /> : label || (environment || "Not set (treated as production)")}
      </span>
      <select aria-label="Environment" value={environment} disabled={pending} onChange={(e) => set(e.target.value)}
        className="rounded-md border border-border bg-surface-2 px-1 py-0.5 text-muted outline-none hover:border-accent/40 disabled:opacity-50">
        {!environment && <option value="">Set environment…</option>}
        {ENVS.map((e) => <option key={e.value} value={e.value}>{e.label}</option>)}
      </select>
      {!environment && suggested && (
        <button onClick={() => set(suggested)} disabled={pending} className="text-faint hover:text-accent">
          looks like {suggested} — confirm?
        </button>
      )}
    </div>
  );
}
