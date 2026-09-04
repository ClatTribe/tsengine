"use client";

import { useParams, useSearchParams } from "next/navigation";
import { useState } from "react";

// Grant-based cloud connect (GCP): the provider console has no OAuth redirect-back, so after the
// customer grants the read-only role we collect the project id here and hit the Go callback
// (/v1/connect/{kind}/callback?code=<project>&state=<state>) to create the connection + first scan.
export default function ConnectSetupPage() {
  const params = useParams();
  const sp = useSearchParams();
  const kind = String(params.kind ?? "");
  const authorizeURL = sp.get("u") ?? "";

  let grantState = "";
  try {
    grantState = new URL(authorizeURL).searchParams.get("state") ?? "";
  } catch {
    /* malformed/expired link — handled below */
  }

  const [projectId, setProjectId] = useState("");
  const label = kind === "gcp" ? "Google Cloud" : kind;

  function finish() {
    const pid = projectId.trim();
    if (!pid || !grantState) return;
    window.location.href = `/v1/connect/${kind}/callback?code=${encodeURIComponent(pid)}&state=${encodeURIComponent(grantState)}`;
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Connect {label}</h1>
        <p className="mt-1.5 text-sm text-muted">Grant read-only access, then tell us which project to scan.</p>
      </div>

      <div className="card space-y-5 p-5">
        <div className="space-y-1.5">
          <div className="text-sm font-medium text-ink">1. Grant read-only access</div>
          <p className="text-xs text-muted">
            Opens the Google Cloud IAM page in a new tab. Grant the shown service account the{" "}
            <span className="font-medium text-ink">Security Reviewer</span> role on your project, then come back here.
          </p>
          <a
            href={authorizeURL}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1.5 rounded-xl bg-surface-2 px-3.5 py-2.5 text-sm font-medium text-accent ring-1 ring-border transition hover:bg-surface"
          >
            Open Google Cloud IAM →
          </a>
        </div>

        <div className="space-y-1.5 border-t border-border pt-5">
          <label className="block text-sm font-medium text-ink">2. Your GCP Project ID</label>
          <input
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            placeholder="e.g. my-project-123456"
            className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm outline-none transition placeholder:text-faint focus:border-accent"
          />
          <p className="text-[11px] text-faint">Find it on the Google Cloud console home or the project picker.</p>
        </div>

        <button
          onClick={finish}
          disabled={!projectId.trim() || !grantState}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-50"
        >
          Connect {label}
        </button>

        {!grantState && (
          <p className="text-xs text-critical">
            This connect link has expired. Go back to Connections and click Connect again.
          </p>
        )}
      </div>
    </div>
  );
}