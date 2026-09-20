"use client";

import { useParams, useSearchParams } from "next/navigation";
import { useState } from "react";

// Grant-based cloud connect (GCP / AWS): the provider console has no OAuth redirect-back, so after the
// customer grants read-only access we collect the account identifier here and hit the Go callback
// (/v1/connect/{kind}/callback?code=<id>&state=<state>) to create the connection + first scan.
const CONFIG: Record<
  string,
  { label: string; grantText: string; idLabel: string; idPlaceholder: string; idHelp: string }
> = {
  gcp: {
    label: "Google Cloud",
    grantText: "Open Google Cloud IAM →",
    idLabel: "GCP Project ID",
    idPlaceholder: "e.g. my-project-123456",
    idHelp: "Find it on the Google Cloud console home or the project picker.",
  },
  aws: {
    label: "AWS",
    grantText: "Launch CloudFormation stack →",
    idLabel: "Role ARN",
    idPlaceholder: "arn:aws:iam::123456789012:role/tsengine-readonly",
    idHelp: "After the CloudFormation stack finishes, copy the RoleArn from its Outputs tab.",
  },
};

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

  const [code, setCode] = useState("");
  const cfg =
    CONFIG[kind] ?? {
      label: kind,
      grantText: "Open provider console →",
      idLabel: "Account identifier",
      idPlaceholder: "",
      idHelp: "",
    };

  function finish() {
    const c = code.trim();
    if (!c || !grantState) return;
    window.location.href = `/v1/connect/${kind}/callback?code=${encodeURIComponent(c)}&state=${encodeURIComponent(grantState)}`;
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Connect {cfg.label}</h1>
        <p className="mt-1.5 text-sm text-muted">Grant read-only access, then tell us what to scan.</p>
      </div>

      <div className="card space-y-5 p-5">
        <div className="space-y-1.5">
          <div className="text-sm font-medium text-ink">1. Grant read-only access</div>
          <p className="text-xs text-muted">
            Opens the {cfg.label} console in a new tab. Follow it to grant the read-only role, then come back here.
          </p>
          <a
            href={authorizeURL}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1 inline-flex items-center gap-1.5 rounded-xl bg-surface-2 px-3.5 py-2.5 text-sm font-medium text-accent ring-1 ring-border transition hover:bg-surface"
          >
            {cfg.grantText}
          </a>
        </div>

        <div className="space-y-1.5 border-t border-border pt-5">
          <label className="block text-sm font-medium text-ink">2. {cfg.idLabel}</label>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={cfg.idPlaceholder}
            className="w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 text-sm outline-none transition placeholder:text-faint focus:border-accent"
          />
          {cfg.idHelp && <p className="text-[11px] text-faint">{cfg.idHelp}</p>}
        </div>

        <button
          onClick={finish}
          disabled={!code.trim() || !grantState}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-accent-hover disabled:opacity-50"
        >
          Connect {cfg.label}
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