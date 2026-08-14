"use client";

import { useState, useTransition } from "react";
import { Database, Loader2, ShieldCheck } from "lucide-react";
import { scanDatabase } from "@/app/(app)/posture/actions";
import type { DatabaseScanResult } from "@/lib/types";

// DatabaseScanPanel — scan the Postgres this company actually runs on.
//
// Every connector we ship is an OAuth app someone has to build and a customer has to authorise:
// GitHub, Okta, M365, the three clouds. A Supabase or Neon database needs none of that — the
// customer already has the connection string, and one request answers "what personal data is in
// here, and who can read it". It was reachable only by curl, which for this segment's most common
// data store is the same as not shipping it.
//
// Two things this surface has to be honest about, because a production connection string is the
// most sensitive thing anyone will paste into this product:
//
//   - WHAT HAPPENS TO THE CREDENTIAL. The server uses it for the request and never stores it, and
//     says so in its own response. We show that back rather than asking the customer to trust an
//     unstated default.
//   - WHAT THE RESULT MEANS. Without value sampling the classification comes from column names,
//     which is a strong hint and not proof. The server says so; the difference matters when
//     someone is deciding whether a table is in scope for GDPR.
export function DatabaseScanPanel() {
  const [dsn, setDsn] = useState("");
  const [sample, setSample] = useState(false);
  const [res, setRes] = useState<DatabaseScanResult | null>(null);
  const [err, setErr] = useState("");
  const [pending, start] = useTransition();

  function run() {
    setErr("");
    setRes(null);
    if (!dsn.trim()) {
      setErr("Paste the connection string first.");
      return;
    }
    start(async () => {
      try {
        const r = await scanDatabase(dsn.trim(), sample);
        setRes(r);
        // Drop the credential from component state the moment it is no longer needed. It was never
        // going to be persisted, but leaving a production DSN sitting in a live form is a needless
        // shoulder-surfing target.
        //
        // Only on SUCCESS. After a failure it is still needed — the usual cause is a typo in the
        // string, and clearing it would make someone retype a 90-character production credential to
        // fix one character. The field is type=password either way.
        setDsn("");
      } catch (e) {
        setErr(e instanceof Error ? e.message : "The scan failed.");
      }
    });
  }

  return (
    <div className="card p-5">
      <div className="flex items-center gap-2.5">
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-accent-soft text-accent">
          <Database className="h-4 w-4" />
        </span>
        <div>
          <div className="text-sm font-semibold text-ink">Scan a database</div>
          <div className="text-xs text-muted">
            Supabase, Neon, RDS or your own Postgres — what personal data it holds, and who can read it.
          </div>
        </div>
      </div>

      <div className="mt-4 space-y-3">
        <input
          value={dsn}
          onChange={(e) => setDsn(e.target.value)}
          type="password"
          autoComplete="off"
          spellCheck={false}
          placeholder="postgres://user:password@host:5432/dbname"
          className="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-ink outline-none focus:border-accent"
        />

        <label className="flex cursor-pointer items-start gap-2 text-xs text-muted">
          <input
            type="checkbox"
            checked={sample}
            onChange={(e) => setSample(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            Read a small sample of values to <span className="text-ink">confirm</span> which tables hold
            personal data. Without this we classify from column names — a strong hint, not proof.
          </span>
        </label>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={run}
            disabled={pending}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-60"
          >
            {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
            {pending ? "Scanning…" : "Scan"}
          </button>
          <span className="text-xs text-faint">Used once. Never stored.</span>
        </div>

        {err && <p className="text-sm text-danger">{err}</p>}

        {res && (
          <div className="rounded-xl border border-border bg-surface-2 p-4">
            <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
              <span className="text-ink">
                {res.tables} <span className="text-muted">tables</span>
              </span>
              <span className="text-ink">
                {res.grants} <span className="text-muted">grants</span>
              </span>
              <span className={res.issues_detected > 0 ? "text-high" : "text-pulse"}>
                {res.issues_detected} <span className="text-muted">issues</span>
              </span>
              {res.schemas_scanned && res.schemas_scanned.length > 0 && (
                <span className="text-xs text-faint">schemas: {res.schemas_scanned.join(", ")}</span>
              )}
            </div>

            {/* The credential statement comes from the server, so this cannot drift from what
                actually happened to it. */}
            {res.credential_retained === false && res.credential_note && (
              <p className="mt-3 flex items-start gap-1.5 text-xs leading-relaxed text-muted">
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-pulse" />
                {res.credential_note}
              </p>
            )}

            {res.deeper_scan_available && (
              <p className="mt-2 text-xs leading-relaxed text-muted">{res.deeper_scan_available}</p>
            )}
            {res.note && <p className="mt-2 text-xs leading-relaxed text-muted">{res.note}</p>}

            {res.findings.length > 0 && (
              <ul className="mt-3 space-y-1.5">
                {res.findings.slice(0, 6).map((f) => (
                  <li key={f.id} className="text-xs">
                    <span className="uppercase text-faint">{f.severity}</span>{" "}
                    <span className="text-ink">{f.title}</span>
                  </li>
                ))}
              </ul>
            )}
            {res.issues_detected > 0 && (
              <p className="mt-3 text-xs text-muted">
                These are now in Issues alongside everything else.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
