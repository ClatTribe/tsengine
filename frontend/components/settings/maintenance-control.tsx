"use client";

import { useState, useTransition } from "react";
import { CalendarClock, Loader2, Plus, Trash2 } from "lucide-react";
import { addMaintenanceWindow, deleteMaintenanceWindow } from "@/app/(app)/settings/actions";
import type { MaintenanceWindow } from "@/lib/types";

// Maintenance / change-freeze windows (MDR/SOC ops). While a window is active the detector opens no
// new incidents and escalation pages no one — so a planned deploy doesn't trip the on-call.
export function MaintenanceControl({ windows }: { windows: MaintenanceWindow[] }) {
  const [name, setName] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [err, setErr] = useState("");
  const [pending, start_] = useTransition();
  const now = Date.now();

  function add() {
    setErr("");
    if (!name.trim() || !start || !end) {
      setErr("Name, start, and end are required");
      return;
    }
    if (new Date(start).getTime() >= new Date(end).getTime()) {
      setErr("Start must be before end");
      return;
    }
    start_(async () => {
      try {
        await addMaintenanceWindow({ name: name.trim(), starts_at: new Date(start).toISOString(), ends_at: new Date(end).toISOString() });
        setName("");
        setStart("");
        setEnd("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to schedule");
      }
    });
  }

  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <CalendarClock className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Maintenance windows</div>
          <div className="text-xs text-muted">Pause alerting during planned work — no incidents open, no one is paged</div>
        </div>
      </div>

      {windows.length > 0 && (
        <ul className="mt-3 space-y-1.5">
          {windows.map((w) => {
            const active = new Date(w.starts_at).getTime() <= now && now < new Date(w.ends_at).getTime();
            const past = new Date(w.ends_at).getTime() <= now;
            return (
              <li key={w.id} className="flex items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-2 text-xs">
                <span className={`h-2 w-2 shrink-0 rounded-full ${active ? "bg-critical" : past ? "bg-faint" : "bg-pulse"}`} />
                <div className="min-w-0 flex-1">
                  <span className="font-medium text-ink">{w.name}</span>
                  {active && <span className="ml-2 rounded-full bg-critical/10 px-1.5 py-0.5 text-[10px] font-semibold text-critical">active now</span>}
                  {!active && !past && <span className="ml-2 text-[10px] text-pulse">scheduled</span>}
                  {past && <span className="ml-2 text-[10px] text-faint">ended</span>}
                  <div className="text-[11px] text-faint">
                    {new Date(w.starts_at).toLocaleString()} → {new Date(w.ends_at).toLocaleString()}
                  </div>
                </div>
                <DeleteBtn id={w.id} />
              </li>
            );
          })}
        </ul>
      )}

      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto_auto_auto]">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Q3 release deploy"
          className="rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs text-ink placeholder:text-faint"
        />
        <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} className="rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-ink" />
        <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} className="rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-ink" />
        <button
          onClick={add}
          disabled={pending}
          className="inline-flex items-center justify-center gap-1 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />} Schedule
        </button>
      </div>
      {err && <p className="mt-1.5 text-[11px] text-critical">{err}</p>}
    </div>
  );
}

function DeleteBtn({ id }: { id: string }) {
  const [pending, start] = useTransition();
  return (
    <button
      onClick={() => start(() => deleteMaintenanceWindow(id))}
      disabled={pending}
      title="Cancel window"
      className="shrink-0 text-faint transition hover:text-critical disabled:opacity-50"
    >
      {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
    </button>
  );
}
