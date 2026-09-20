"use client";

import { useState, useTransition } from "react";
import { Users, Loader2, Check, RefreshCw } from "lucide-react";
import { setHRIS, syncHRIS } from "@/app/(app)/settings/actions";
import type { HRISSettings, HRISSyncResult } from "@/lib/types";

// Per-tenant HR-system source (Bucket B). Credentials are sealed server-side and never shown again.
// "Sync now" fetches the roster and joins it against every connected identity provider; the platform
// repeats the join from the stored roster on every monitoring pass.
const LABELS: Record<string, string> = { merge: "Merge.dev", finch: "Finch" };

export function HRISControl({ config }: { config: HRISSettings }) {
  const [provider, setProvider] = useState(config.provider || "merge");
  const [apiKey, setApiKey] = useState("");
  const [accountToken, setAccountToken] = useState("");
  const [state, setState] = useState<HRISSettings>(config);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [sync, setSync] = useState<HRISSyncResult | null>(null);
  const [syncErr, setSyncErr] = useState("");
  const [pending, start] = useTransition();
  const [syncing, startSync] = useTransition();

  const configured = !!state.provider;

  function save(clear: boolean) {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setHRIS(
          clear ? { provider: "", api_key: "", account_token: "" } : { provider, api_key: apiKey.trim(), account_token: accountToken.trim() },
        );
        setState(r);
        setProvider(r.provider || "merge");
        setApiKey("");
        setAccountToken("");
        setSaved(true);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Failed to save");
      }
    });
  }

  function runSync() {
    setSyncErr("");
    setSync(null);
    startSync(async () => {
      try {
        const r = await syncHRIS();
        setSync(r);
        setState((s) => ({ ...s, employees: r.employees, last_synced_at: new Date().toISOString() }));
      } catch (e) {
        setSyncErr(e instanceof Error ? e.message : "Sync failed");
      }
    });
  }

  const cls = "mono w-full rounded-md border border-border bg-surface px-2 py-1 text-xs text-ink placeholder:text-faint";
  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3.5 py-3">
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-surface text-muted">
          <Users className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">HR system (joiners &amp; leavers)</div>
          <div className="text-xs text-muted">Employment records joined against your identity provider — a leaver whose account is still enabled becomes a finding</div>
        </div>
        <span className={`text-[11px] ${configured ? "text-accent" : "text-faint"}`}>
          {configured ? `${LABELS[state.provider] ?? state.provider} · ${state.employees} record${state.employees === 1 ? "" : "s"}` : "not set"}
        </span>
      </div>

      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
        <select value={provider} onChange={(e) => setProvider(e.target.value)} className={cls}>
          {(state.providers ?? ["merge", "finch"]).map((p) => (
            <option key={p} value={p}>{LABELS[p] ?? p}</option>
          ))}
        </select>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={state.has_key ? (provider === "merge" ? "API key (leave blank to keep)" : "Access token (leave blank to keep)") : provider === "merge" ? "Merge API key" : "Finch employer access token"}
          className={cls}
        />
        {provider === "merge" && (
          <input
            type="password"
            value={accountToken}
            onChange={(e) => setAccountToken(e.target.value)}
            placeholder={state.has_account_token ? "Linked-account token (leave blank to keep)" : "Linked-account token"}
            className={cls}
          />
        )}
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          onClick={() => save(false)}
          disabled={pending}
          className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1 text-xs font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {pending ? <Loader2 className="h-3 w-3 animate-spin" /> : saved ? <Check className="h-3 w-3" /> : null}
          {saved ? "Saved" : "Save"}
        </button>
        {configured && (
          <>
            <button
              onClick={runSync}
              disabled={syncing}
              title="Fetch the roster now and check every account against employment"
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-medium text-muted transition hover:border-accent/40 hover:text-accent disabled:opacity-50"
            >
              {syncing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
              Sync now
            </button>
            <button
              onClick={() => save(true)}
              disabled={pending}
              className="rounded-md border border-border px-2 py-1 text-xs text-muted transition hover:border-critical/40 hover:text-critical disabled:opacity-50"
            >
              Clear
            </button>
          </>
        )}
        {state.last_synced_at && !sync && <span className="text-[11px] text-faint">last synced {new Date(state.last_synced_at).toLocaleString()}</span>}
        {err && <span className="text-[11px] text-critical">{err}</span>}
        {syncErr && <span className="text-[11px] text-critical">{syncErr}</span>}
      </div>

      {sync && (
        <div className="mt-2 rounded-md border border-border bg-surface px-2.5 py-2 text-[11px]">
          <div className="text-accent">
            {sync.employees} employee record{sync.employees === 1 ? "" : "s"} from {LABELS[sync.provider] ?? sync.provider} ·{" "}
            {sync.joined
              ? sync.issues_detected === 0
                ? "every account matched employment — no leavers with access"
                : `${sync.issues_detected} finding${sync.issues_detected === 1 ? "" : "s"} → Issues`
              : "roster stored, but the join did not run"}
          </div>
          {/* Why the join could not conclude something. A roster with no identity provider to join
              against is not a clean offboarding process, and this is where that is said. */}
          {sync.checks_not_run && sync.checks_not_run.length > 0 && (
            <ul className="mt-1 list-disc space-y-0.5 pl-4 text-muted">
              {sync.checks_not_run.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
