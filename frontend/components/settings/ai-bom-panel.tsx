import { ShieldCheck, KeyRound, Pencil, Eye } from "lucide-react";
import type { AIBom } from "@/lib/types";
import { cn } from "@/lib/utils";

// The AI-BOM panel (agent capability manifest, WRD-1): the least-privilege view of what
// the autonomous agent can actually touch — every connected system + a read/write
// classification of its granted scopes. Write-capable connections are the higher-risk
// surface a hijacked agent could mutate. Server-rendered, presentational.
export function AIBomPanel({ bom }: { bom: AIBom | null }) {
  if (!bom || bom.connections.length === 0) {
    return (
      <p className="rounded-xl border border-border bg-surface px-4 py-3 text-xs text-muted">
        Connect a system to see exactly what your automated security agent can access.
      </p>
    );
  }
  const { summary } = bom;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <Stat label="Systems" value={summary.connections} tone="neutral" />
        <Stat label="Read-only" value={summary.read_only} tone="ok" />
        <Stat label="Write-capable" value={summary.write_capable} tone={summary.write_capable > 0 ? "high" : "ok"} />
      </div>
      <ul className="divide-y divide-border overflow-hidden rounded-xl border border-border">
        {bom.connections.map((c, i) => {
          const write = c.capability === "read-write";
          return (
            <li key={i} className="flex items-center justify-between gap-3 bg-surface px-4 py-2.5">
              <div className="min-w-0">
                <div className="text-sm font-medium capitalize">{c.kind}</div>
                {c.account && <div className="mono truncate text-[11px] text-faint">{c.account}</div>}
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {c.write_scopes && c.write_scopes.length > 0 && (
                  <span className="mono hidden text-[10px] text-muted sm:inline">{c.write_scopes.join(", ")}</span>
                )}
                <span
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium",
                    write ? "bg-high/10 text-high ring-1 ring-high/30" : "bg-pulse/10 text-pulse ring-1 ring-pulse/30",
                  )}
                >
                  {write ? <Pencil className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                  {write ? "read-write" : "read-only"}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="flex items-center gap-1.5 text-[11px] text-faint">
        <ShieldCheck className="h-3.5 w-3.5" />
        Every write is human-gated at tier {bom.governance.gate_tier}+; the kill-switch freezes all of it.
      </p>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: "neutral" | "ok" | "high" }) {
  return (
    <div className="rounded-xl border border-border bg-surface px-3 py-2.5 text-center">
      <div className={cn("text-lg font-semibold", tone === "high" && "text-high", tone === "ok" && "text-pulse")}>{value}</div>
      <div className="flex items-center justify-center gap-1 text-[10px] uppercase tracking-wide text-faint">
        {label === "Write-capable" && <KeyRound className="h-2.5 w-2.5" />}
        {label}
      </div>
    </div>
  );
}
