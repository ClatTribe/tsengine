"use client";

import { useState, useTransition } from "react";
import { Laptop, Loader2, Check, RefreshCw } from "lucide-react";
import { setMDM, syncDevices } from "@/app/(app)/settings/actions";
import type { MDMSettings, DeviceSyncResult } from "@/lib/types";

// Per-tenant device-management source (Bucket B). Provider + base URL are plain; every credential is
// sealed server-side and never shown again. "Sync now" fetches the fleet live; the platform repeats
// it on every monitoring pass once a source is configured.
const LABELS: Record<string, string> = { kandji: "Kandji", jamf: "Jamf Pro", intune: "Microsoft Intune" };

export function MDMControl({ config }: { config: MDMSettings }) {
  const [provider, setProvider] = useState(config.provider || "kandji");
  const [baseUrl, setBaseUrl] = useState(config.base_url);
  const [token, setToken] = useState("");
  const [clientId, setClientId] = useState(config.client_id);
  const [clientSecret, setClientSecret] = useState("");
  const [state, setState] = useState<MDMSettings>(config);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [sync, setSync] = useState<DeviceSyncResult | null>(null);
  const [syncErr, setSyncErr] = useState("");
  const [pending, start] = useTransition();
  const [syncing, startSync] = useTransition();

  const configured = !!state.provider;
  const needsBase = provider === "kandji" || provider === "jamf";
  const intuneBorrows = provider === "intune" && !state.has_token && state.m365_connected;

  function save(clear: boolean) {
    setErr("");
    setSaved(false);
    start(async () => {
      try {
        const r = await setMDM(
          clear
            ? { provider: "", base_url: "", api_token: "", client_id: "", client_secret: "" }
            : { provider, base_url: baseUrl.trim(), api_token: token.trim(), client_id: clientId.trim(), client_secret: clientSecret.trim() },
        );
        setState(r);
        setProvider(r.provider || "kandji");
        setBaseUrl(r.base_url);
        setClientId(r.client_id);
        setToken("");
        setClientSecret("");
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
        setSync(await syncDevices());
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
          <Laptop className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium">Device management (MDM)</div>
          <div className="text-xs text-muted">Laptop disk encryption, tampering and OS posture, read from your MDM on every monitoring pass</div>
        </div>
        <span className={`text-[11px] ${configured ? "text-accent" : "text-faint"}`}>
          {configured ? `${LABELS[state.provider] ?? state.provider} configured` : "not set"}
        </span>
      </div>

      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
        <select value={provider} onChange={(e) => setProvider(e.target.value)} className={cls}>
          {(state.providers ?? ["kandji", "jamf", "intune"]).map((p) => (
            <option key={p} value={p}>{LABELS[p] ?? p}</option>
          ))}
        </select>
        {needsBase ? (
          <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder={provider === "kandji" ? "https://acme.api.kandji.io" : "https://acme.jamfcloud.com"} className={cls} />
        ) : (
          <div className="self-center text-[11px] text-muted">
            {intuneBorrows ? "Uses your connected Microsoft 365 tenant (needs DeviceManagementManagedDevices.Read.All)" : "Microsoft Graph — paste a token, or connect Microsoft 365"}
          </div>
        )}
        {provider === "jamf" && (
          <>
            <input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="API client id (optional)" className={cls} />
            <input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder={state.has_client_secret ? "Client secret (leave blank to keep)" : "Client secret"} className={cls} />
          </>
        )}
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={state.has_token ? "API token (leave blank to keep)" : provider === "jamf" ? "Bearer token (if no API client)" : "API token"}
          className={cls}
        />
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          onClick={() => save(false)}
          disabled={pending || (needsBase && !baseUrl.trim())}
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
              title="Read the fleet from your MDM now and assess it"
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
        {err && <span className="text-[11px] text-critical">{err}</span>}
        {syncErr && <span className="text-[11px] text-critical">{syncErr}</span>}
      </div>

      {sync && (
        <div className="mt-2 rounded-md border border-border bg-surface px-2.5 py-2 text-[11px]">
          <div className="text-accent">
            {sync.devices} device{sync.devices === 1 ? "" : "s"} read from {LABELS[sync.provider] ?? sync.provider} ·{" "}
            {sync.issues_detected === 0 ? "no posture issues" : `${sync.issues_detected} finding${sync.issues_detected === 1 ? "" : "s"} → Issues`}
          </div>
          {/* What the sync could NOT assess. Without this, "0 issues" over a fleet whose MDM cannot
              report firewalls reads as "firewalls are on". */}
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
