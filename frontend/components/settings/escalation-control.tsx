"use client";

import { useState, useTransition } from "react";
import { SignalHigh, Loader2, Check, Plus, Trash2 } from "lucide-react";
import { setEscalation } from "@/app/(app)/settings/actions";
import type { EscalationPolicy, EscalationTier } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low"];
const CHANNELS = ["slack", "pagerduty", "teams", "discord", "webhook"];

// Incident escalation matrix (MDR/SOC parity). The owner builds tiers of "severity → channels";
// a new incident is routed to the first tier whose severity it meets (e.g. critical → pagerduty +
// slack, high → slack). Maps to the contractual "escalation matrix with contact number".
export function EscalationControl({ policy }: { policy: EscalationPolicy }) {
  const [enabled, setEnabled] = useState(policy.enabled);
  const [ackWindow, setAckWindow] = useState(policy.ack_window_mins || 0);
  const [tiers, setTiers] = useState<EscalationTier[]>(
    policy.tiers?.length ? policy.tiers : [{ min_severity: "critical", channels: ["slack"] }],
  );
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [pending, start] = useTransition();

  function setTier(i: number, patch: Partial<EscalationTier>) {
    setTiers((ts) => ts.map((t, j) => (j === i ? { ...t, ...patch } : t)));
  }
  function toggleChannel(i: number, ch: string) {
    setTiers((ts) =>
      ts.map((t, j) => {
        if (j !== i) return t;
        const has = t.channels.includes(ch);
        return { ...t, channels: has ? t.channels.filter((c) => c !== ch) : [...t.channels, ch] };
      }),
    );
  }

  function save() {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setEscalation({ enabled, ack_window_mins: Number(ackWindow) || 0, tiers });
        setEnabled(r.enabled);
        setTiers(r.tiers?.length ? r.tiers : tiers);
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
          <SignalHigh className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Escalation matrix</div>
          <div className="text-xs text-muted">Route new incidents by severity to the right channels</div>
        </div>
        <label className="flex items-center gap-1.5 text-xs text-ink">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
      </div>

      <div className="mt-3 space-y-2">
        {tiers.map((t, i) => (
          <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-2">
            <span className="text-[11px] text-faint">at/above</span>
            <select
              value={t.min_severity}
              onChange={(e) => setTier(i, { min_severity: e.target.value })}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-ink capitalize"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="text-[11px] text-faint">→</span>
            <div className="flex flex-wrap gap-1">
              {CHANNELS.map((ch) => {
                const on = t.channels.includes(ch);
                return (
                  <button
                    key={ch}
                    onClick={() => toggleChannel(i, ch)}
                    className={`rounded-md border px-2 py-0.5 text-[11px] capitalize transition ${
                      on ? "border-accent/40 bg-accent/10 text-accent" : "border-border text-muted hover:border-accent/40"
                    }`}
                  >
                    {ch}
                  </button>
                );
              })}
            </div>
            {tiers.length > 1 && (
              <button
                onClick={() => setTiers((ts) => ts.filter((_, j) => j !== i))}
                className="ml-auto text-faint transition hover:text-critical"
                title="Remove tier"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => setTiers((ts) => [...ts, { min_severity: "high", channels: ["slack"] }])}
          className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] text-muted transition hover:border-accent/40 hover:text-accent"
        >
          <Plus className="h-3 w-3" /> Add tier
        </button>
      </div>

      <div className="mt-3 flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-[11px] text-muted">
          Auto-escalate if unacknowledged after
          <input
            type="number"
            min={0}
            value={ackWindow}
            onChange={(e) => setAckWindow(Number(e.target.value))}
            className="w-16 rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink"
          />
          min (0 = off)
        </label>
        <button
          onClick={save}
          disabled={pending}
          className="ml-auto inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {saved ? "Saved" : "Save"}
        </button>
      </div>
      <p className="mt-1.5 text-[11px] text-faint">
        Channels must be provisioned by your administrator. Unconfigured channels fall back to the default alert.
      </p>
      {err && <p className="mt-1 text-[11px] text-critical">{err}</p>}
    </div>
  );
}
