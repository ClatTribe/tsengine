"use client";

import { useState, useTransition } from "react";
import { ShieldCheck, Loader2, Check, ArrowUpRight, RefreshCw } from "lucide-react";
import { setDrata, syncDrata } from "@/app/(app)/settings/actions";
import type { DrataSettings } from "@/lib/types";

// Push-to-Drata. The engine's control posture becomes records in the customer's Drata that THEIR
// tests evaluate — the honest shape: we hand over what we assessed (met/gap per control, the finding
// count, an evidence link), Drata's dashboard test decides pass/fail and maps it to the control. We
// never tell Drata a control is met.
export function DrataControl({ initial }: { initial: DrataSettings }) {
  const [key, setKey] = useState("");
  const [ws, setWs] = useState(initial.workspace_id ? String(initial.workspace_id) : "");
  const [state, setState] = useState<DrataSettings>(initial);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [saving, startSave] = useTransition();
  const [syncing, startSync] = useTransition();

  function save(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setMsg("");
    startSave(async () => {
      try {
        const r = await setDrata({ api_key: key, workspace_id: Number(ws) || 0 });
        setState(r); setKey(""); setMsg(r.has_key ? "Connected." : "Cleared.");
      } catch (ex) { setErr(ex instanceof Error ? ex.message : "could not save"); }
    });
  }
  function sync() {
    setErr(""); setMsg("");
    startSync(async () => {
      try {
        const r = await syncDrata();
        setMsg(`Pushed ${r.pushed} control${r.pushed === 1 ? "" : "s"} to Drata.`);
      } catch (ex) { setErr(ex instanceof Error ? ex.message : "sync failed"); }
    });
  }

  return (
    <div className="space-y-3">
      <p className="text-xs leading-relaxed text-muted">
        Push your control posture into Drata as evidence records. You author the pass/fail test over them in
        Drata and map it to a control — we hand over what we assessed, your test decides. A control we have not
        assessed is simply not sent (never a false &quot;met&quot;).{" "}
        <a href="https://developers.drata.com/developer-portal/v2/recipes/custom-connections/" target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 font-medium text-accent hover:underline">
          Drata custom connections <ArrowUpRight className="h-3 w-3" />
        </a>
      </p>
      <form onSubmit={save} className="grid gap-2 sm:grid-cols-[1fr_10rem_auto]">
        <input value={key} onChange={(e) => setKey(e.target.value)} type="password" autoComplete="off"
          placeholder={state.has_key ? "API key set — enter a new one to replace" : "Drata API key"}
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        <input value={ws} onChange={(e) => setWs(e.target.value)} inputMode="numeric" placeholder="Workspace ID"
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none transition focus:border-accent" />
        <button type="submit" disabled={saving}
          className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-white transition hover:bg-accent-hover active:translate-y-px disabled:opacity-60">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />} {state.has_key ? "Update" : "Connect"}
        </button>
      </form>
      {state.has_key && (
        <div className="flex flex-wrap items-center gap-3">
          <button onClick={sync} disabled={syncing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-1.5 text-sm font-medium transition hover:border-accent/40 disabled:opacity-60">
            {syncing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Sync posture now
          </button>
          <span className="text-xs text-faint">{state.connected ? "Connection established — a sync replaces the previous batch." : "Not yet synced."}</span>
        </div>
      )}
      {msg && <p className="inline-flex items-center gap-1 text-xs text-pulse"><Check className="h-3.5 w-3.5" /> {msg}</p>}
      {err && <p className="text-xs text-critical">{err}</p>}
    </div>
  );
}
