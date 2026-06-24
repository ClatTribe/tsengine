"use client";

import { useState, useTransition } from "react";
import { Timer, Loader2, Check } from "lucide-react";
import { setSLA } from "@/app/(app)/settings/actions";
import type { SLAPolicy, SLATarget } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low"];

// Default targets when none are set — sensible MDR-grade SLAs the owner can tune.
const DEFAULTS: Record<string, { ack: number; resolve: number }> = {
  critical: { ack: 1, resolve: 24 },
  high: { ack: 4, resolve: 72 },
  medium: { ack: 24, resolve: 168 },
  low: { ack: 72, resolve: 720 },
};

// Remediation SLA policy (MDR / vuln-mgmt parity). Per-severity time-to-acknowledge + time-to-
// resolve targets, in hours; a new incident is measured against them and flagged when breached.
export function SLAControl({ policy }: { policy: SLAPolicy }) {
  const [enabled, setEnabled] = useState(policy.enabled);
  const bySev = new Map(policy.targets?.map((t) => [t.severity, t]));
  const [rows, setRows] = useState<SLATarget[]>(
    SEVERITIES.map((s) => bySev.get(s) ?? { severity: s, ack_hours: DEFAULTS[s].ack, resolve_hours: DEFAULTS[s].resolve }),
  );
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function setRow(sev: string, patch: Partial<SLATarget>) {
    setRows((rs) => rs.map((r) => (r.severity === sev ? { ...r, ...patch } : r)));
  }

  function save() {
    setErr("");
    setSaved(false);
    // Only ship targets with at least one non-zero clock (the API rejects all-zero).
    const targets = rows.filter((r) => r.ack_hours > 0 || r.resolve_hours > 0);
    start(async () => {
      try {
        const r = await setSLA({ enabled, targets });
        setEnabled(r.enabled);
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Timer className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Remediation SLAs</div>
          <div className="text-xs text-muted">Time-to-acknowledge &amp; time-to-resolve targets, by severity</div>
        </div>
        <label className="flex items-center gap-1.5 text-xs text-ink">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
      </div>

      <div className="mt-3 overflow-hidden rounded-lg border border-border">
        <div className="grid grid-cols-[1fr_auto_auto] items-center gap-2 bg-surface px-3 py-1.5 text-[11px] font-medium text-faint">
          <span>Severity</span>
          <span className="w-24 text-right">Ack (h)</span>
          <span className="w-24 text-right">Resolve (h)</span>
        </div>
        {rows.map((r) => (
          <div key={r.severity} className="grid grid-cols-[1fr_auto_auto] items-center gap-2 border-t border-border bg-surface px-3 py-1.5">
            <span className="text-xs capitalize text-ink">{r.severity}</span>
            <input
              type="number"
              min={0}
              value={r.ack_hours}
              onChange={(e) => setRow(r.severity, { ack_hours: Number(e.target.value) })}
              className="w-24 rounded-md border border-border bg-surface-2 px-2 py-1 text-right text-xs text-ink"
            />
            <input
              type="number"
              min={0}
              value={r.resolve_hours}
              onChange={(e) => setRow(r.severity, { resolve_hours: Number(e.target.value) })}
              className="w-24 rounded-md border border-border bg-surface-2 px-2 py-1 text-right text-xs text-ink"
            />
          </div>
        ))}
      </div>

      <div className="mt-3 flex items-center gap-3">
        <p className="text-[11px] text-faint">0 hours disables that clock. Breaches show on the Incidents page.</p>
        <button
          onClick={save}
          disabled={pending}
          className="ml-auto inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {saved ? "Saved" : "Save"}
        </button>
      </div>
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}
